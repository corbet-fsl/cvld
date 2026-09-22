import { requirePositive, requireText } from './encoding.js';

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...headers } });
}

export function createEntryHandler(options) {
  const entry = options?.entry;
  if (!entry || typeof entry.beginRegistration !== 'function' || typeof entry.finishRegistration !== 'function' || typeof entry.beginAuthentication !== 'function' || typeof entry.finishAuthentication !== 'function') throw new TypeError('Entry service required');
  const origin = requireText(options.origin, 'origin');
  const configuredOrigin = new URL(origin);
  if (configuredOrigin.origin !== origin) throw new TypeError('Origin must be an origin URL');
  const maxBodyBytes = requirePositive(options.maxBodyBytes, 'request body capacity');
  const cookieLifetime = requirePositive(options.cookieLifetimeSeconds, 'cookie lifetime');
  const sessionCookie = requireText(options.sessionCookie, 'session cookie name');
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(sessionCookie)) throw new TypeError('Invalid session cookie name');
  const allowInsecureLocalhost = options.allowInsecureLocalhost === true;
  const apiKeys = options.apiKeys;
  function sameOrigin(request) {
    const supplied = request.headers.get('origin');
    return supplied === origin;
  }
  function httpsRequest(request) {
    const url = new URL(request.url);
    return url.protocol === 'https:';
  }
  function allowedTransport(request) {
    const url = new URL(request.url);
    if (url.origin !== configuredOrigin.origin) return false;
    if (httpsRequest(request)) return true;
    return allowInsecureLocalhost && url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]');
  }
  async function body(request) {
    if (request.headers.get('content-type')?.toLowerCase() !== 'application/json') throw new Error('Request rejected');
    const length = request.headers.get('content-length');
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBodyBytes)) throw new Error('Request rejected');
    if (!request.body) throw new Error('Request rejected');
    const reader = request.body.getReader();
    const chunks = []; let size = 0;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > maxBodyBytes) throw new Error('Request rejected');
        chunks.push(part.value);
      }
    } catch (error) { await reader.cancel(); throw error; }
    finally { reader.releaseLock(); }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  }
  function setSessionCookie(request, sessionId, maxAge) {
    const secure = httpsRequest(request);
    if (!allowedTransport(request)) throw new Error('HTTPS required');
    return { 'set-cookie': `${sessionCookie}=${encodeURIComponent(sessionId)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}` };
  }
  function sessionIdFromCookie(request) {
    const cookie = request.headers.get('cookie')?.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${sessionCookie}=`));
    return cookie ? decodeURIComponent(cookie.slice(sessionCookie.length + 1)) : '';
  }
  function authenticatedPrincipal(request, scope) {
    if (!allowedTransport(request)) return false;
    const suppliedOrigin = request.headers.get('origin');
    const sessionId = sessionIdFromCookie(request);
    const authorization = request.headers.get('authorization') ?? '';
    const match = /^Bearer (\S+)$/.exec(authorization);
    const bearerOnly = !sessionId && Boolean(match);
    if (suppliedOrigin !== null && suppliedOrigin !== origin) return false;
    if (sessionId && request.method !== 'GET' && suppliedOrigin !== origin) return false;
    if (request.method !== 'GET' && suppliedOrigin !== origin && !bearerOnly) return false;
    const current = (principal) => {
      const value = entry.isCurrentMember(principal.memberId);
      return value && typeof value.then === 'function' ? value.then(ok => ok ? principal : false) : value ? principal : false;
    };
    const bearerPrincipal = () => {
      if (!match || !apiKeys || typeof apiKeys.authenticate !== 'function' || typeof entry.isCurrentMember !== 'function') return false;
      const value = apiKeys.authenticate(match[1], scope);
      const checked = principal => principal ? current(principal) : false;
      return value && typeof value.then === 'function' ? value.then(checked) : checked(value);
    };
    const sessionPrincipal = session => session && typeof session.memberId === 'string' ? { kind: 'session', sessionId, memberId: session.memberId } : false;
    const inspectSession = session => {
      const principal = sessionPrincipal(session);
      if (!principal) return bearerPrincipal();
      // authenticatedSession already checks membership and then rechecks the
      // live session after that awaited read. Do not introduce another read
      // after its revocation check.
      if (typeof entry.authenticatedSession === 'function') return principal;
      if (typeof entry.isCurrentMember !== 'function') return principal;
      const value = current(principal);
      const checked = result => {
        const live = entry.getSession?.(sessionId);
        return result && live?.memberId === session.memberId && live.expiresAt === session.expiresAt ? result : bearerPrincipal();
      };
      return value && typeof value.then === 'function' ? value.then(checked) : checked(value);
    };
    if (sessionId) {
      const session = typeof entry.authenticatedSession === 'function'
        ? entry.authenticatedSession(sessionId)
        : typeof entry.getSession === 'function' ? entry.getSession(sessionId) : false;
      if (session && typeof session.then === 'function') return session.then(inspectSession);
      return inspectSession(session);
    }
    return bearerPrincipal();
  }
  const handle = async function handle(request) {
    try {
      const url = new URL(request.url);
      const route = `${request.method} ${url.pathname}`;
      if (!allowedTransport(request)) return json(400, { error: 'HTTPS required' });
      const sessionId = sessionIdFromCookie(request);
      const bearerCredentialOnly = request.method === 'POST' &&
        (url.pathname === '/credential/begin' || url.pathname === '/credential/issue') &&
        !sessionId && /^Bearer (\S+)$/.test(request.headers.get('authorization') ?? '');
      if (request.method !== 'GET' && !sameOrigin(request) && !bearerCredentialOnly) return json(403, { error: 'request rejected' });
      if (route === 'POST /auth/register/begin') return json(200, await entry.beginRegistration(await body(request)));
      if (route === 'POST /auth/register/precommit') {
        if (typeof entry.beginRegistrationPrecommit !== 'function') return json(404, { error: 'not found' });
        return json(200, await entry.beginRegistrationPrecommit(await body(request)) || { ok: false });
      }
      if (route === 'POST /auth/register/finish') {
        const result = await entry.finishRegistration(await body(request));
        if (!result) return json(401, { ok: false });
        const { sessionId, ...publicResult } = result;
        return json(200, publicResult, setSessionCookie(request, sessionId, cookieLifetime));
      }
      if (route === 'POST /auth/login/begin') return json(200, await entry.beginAuthentication());
      if (route === 'POST /auth/login/finish') {
        const result = await entry.finishAuthentication(await body(request));
        if (!result) return json(401, { ok: false });
        const { sessionId, ...publicResult } = result;
        return json(200, publicResult, setSessionCookie(request, sessionId, cookieLifetime));
      }
      if (route === 'POST /auth/logout') {
        const sessionId = sessionIdFromCookie(request);
        if (sessionId) entry.revokeSession(sessionId);
        return json(200, { ok: true }, { 'set-cookie': `${sessionCookie}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict${httpsRequest(request) ? '; Secure' : ''}` });
      }
      if (route === 'POST /auth/rebind') {
        const input = await body(request);
        const result = await entry.rebindDevice({ chatPublicKey: input?.chatPublicKey, authorization: input?.authorization, sessionId: sessionIdFromCookie(request) });
        return result ? json(200, result) : json(401, { ok: false });
      }
      if (route === 'POST /auth/api-keys') {
        const input = await body(request);
        const principal = await authenticatedPrincipal(request, 'api-key:manage');
        if (!principal || principal.kind !== 'session' || !apiKeys?.create) return json(401, { ok: false });
        return json(200, await apiKeys.create({ memberId: principal.memberId, name: input?.name, scopes: input?.scopes, expiresAt: input?.expiresAt }));
      }
      if (route === 'GET /auth/api-keys') {
        const principal = await authenticatedPrincipal(request, 'api-key:manage');
        if (!principal || principal.kind !== 'session' || !apiKeys?.list) return json(401, { ok: false });
        return json(200, await apiKeys.list(principal.memberId));
      }
      if (route === 'POST /auth/api-keys/revoke') {
        const input = await body(request);
        const principal = await authenticatedPrincipal(request, 'api-key:manage');
        if (!principal || principal.kind !== 'session' || !apiKeys?.revoke) return json(401, { ok: false });
        return json(200, { ok: await apiKeys.revoke({ memberId: principal.memberId, id: input?.id }) });
      }
      if (route === 'POST /credential/begin') {
        const principal = await authenticatedPrincipal(request, 'credentials:issue');
        const result = principal ? await entry.beginCredential({ principal }) : false;
        return result ? json(200, result) : json(401, { ok: false });
      }
      if (route === 'POST /credential/issue') {
        const input = await body(request);
        const principal = await authenticatedPrincipal(request, 'credentials:issue');
        const result = principal ? await entry.issueCredential({ principal, id: input?.id, request: input?.request }) : false;
        return result ? json(200, result) : json(401, { ok: false });
      }
      if (route === 'GET /auth/session') {
        const sessionId = sessionIdFromCookie(request);
        const session = sessionId ? entry.getSession(sessionId) : false;
        return session ? json(200, session) : json(401, { ok: false });
      }
      return json(404, { error: 'not found' });
    } catch { return json(400, { error: 'request rejected' }); }
  };
  handle.authenticatedPrincipal = authenticatedPrincipal;
  return handle;
}
