# Turso state adapter

`createTursoState` is the asynchronous durable counterpart to
`createSqliteState`. It accepts only trusted server configuration:

```js
const state = await createTursoState({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
  clock,
  networkTimeoutMs,
  maxReceipts,
  maxCredentials,
  maxVoucherSpends,
});
```

Remote configuration requires an `https:` or `libsql:` URL with no embedded
credentials, query, or fragment, plus an explicit `networkTimeoutMs`. The
adapter uses the SDK HTTP client and carries the abort signal through response
body consumption.

The URL, token, and timeout must remain server-side configuration. Browser input never
selects a database or supplies an auth token. The adapter keeps the existing
repository names (`receipts`, `credentials`, and `members`) but its methods are
async because `@libsql/client` is async. `createEntryService` awaits these
boundaries, so the synchronous SQLite repositories continue to work unchanged.

Voucher redemption inserts the voucher spend, member binding, and first
passkey in one libSQL write transaction. Credential counters use a conditional
update, so a lower or equal counter cannot win a race. Receipt issuance and
API-key creation, authentication, listing, and revocation also use write
transactions. API keys store only SHA-256 token digests and return the secret
once from creation.

`test/turso-contract.test.js` always exercises the adapter against a temporary
local-file libSQL client. Its optional remote case uses a dedicated database
only when `CVLD_TURSO_TEST=1` and the Turso environment variables are present.
Resolve the pinned `@libsql/client` dependency and retain the resulting lockfile
in remote CI.
