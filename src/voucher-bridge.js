import { execFile } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { requirePositive, requireText } from './encoding.js';
import { publicBytes } from './admission.js';

export function createVoucherBridge(options) {
  const executable = requireText(options?.executable, 'voucher bridge executable');
  if (!isAbsolute(executable)) throw new TypeError('Voucher bridge executable must be absolute');
  const timeoutMs = requirePositive(options.timeoutMs, 'voucher bridge timeout');
  const maxRequestBytes = requirePositive(options.maxRequestBytes, 'voucher request capacity');
  const maxResponseBytes = requirePositive(options.maxResponseBytes, 'voucher response capacity');
  if (maxRequestBytes > 64 * 1024 || maxResponseBytes > 16 * 1024) throw new TypeError('Voucher bridge capacity exceeds protocol bound');
  const args = options.args;
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) throw new TypeError('Voucher bridge arguments required');
  const fixedArgs = Object.freeze([...args]);
  async function invoke(request) {
    const encoded = JSON.stringify(request);
    if (Buffer.byteLength(encoded) + 1 > maxRequestBytes) return false;
    try {
      const output = await new Promise((resolve, reject) => {
        const child = execFile(executable, fixedArgs, { encoding: 'utf8', timeout: timeoutMs, maxBuffer: maxResponseBytes, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }, (error, stdout) => {
          if (error) reject(error); else resolve(stdout);
        });
        child.stdin.end(`${encoded}\n`);
      });
      if (Buffer.byteLength(output) > maxResponseBytes) return false;
      return JSON.parse(output);
    } catch { return false; }
  }
  async function verifyVoucher({ voucher, communityId, sponsorPublicKey, memberId, now }) {
    try {
      requireText(communityId, 'community ID'); publicBytes(sponsorPublicKey); publicBytes(memberId); requirePositive(now, 'clock');
      if (!voucher || typeof voucher !== 'object' || Array.isArray(voucher) || typeof voucher.id !== 'string' ||
          !Number.isSafeInteger(voucher.valid_until) || voucher.valid_until <= 0 || typeof voucher.signature !== 'string') return false;
      const result = await invoke({ op: 'verify', voucher, community_id: communityId, sponsor_public_key: sponsorPublicKey, member_id: memberId, now_secs: now });
      if (result?.ok !== true || typeof result.receipt_id !== 'string' || !/^[0-9a-f]{64}$/.test(result.receipt_id) ||
          typeof result.member_binding !== 'string' || !/^[0-9a-f]{64}$/.test(result.member_binding) || result.valid_until !== voucher.valid_until) return false;
      return Object.freeze({ receiptId: result.receipt_id, memberBinding: result.member_binding, validUntil: result.valid_until });
    } catch { return false; }
  }
  async function verifyDeviceAuthorization({ authorization, communityId, memberId, chatPublicKey, now }) {
    try {
      requireText(communityId, 'community ID'); publicBytes(memberId); publicBytes(chatPublicKey); requirePositive(now, 'clock');
      const result = await invoke({ op: 'verify_device', authorization, community_id: communityId, member_id: memberId, chat_public_key: chatPublicKey, now_secs: now });
      return result?.ok === true;
    } catch { return false; }
  }
  return Object.freeze({ verifyVoucher, verifyDeviceAuthorization });
}
