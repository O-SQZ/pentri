import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';

const DEFAULT_BLOCKED_PORTS = [8787, 11434];
const MAX_PATHS = 20;

function fail(message) {
  throw new Error(message);
}

function ipv4Number(address) {
  return address.split('.').reduce((number, part) => number * 256 + Number(part), 0);
}

function ipv4In(address, prefix, bits) {
  const size = 2 ** (32 - bits);
  return Math.floor(ipv4Number(address) / size) === Math.floor(ipv4Number(prefix) / size);
}

function ipv6Number(address) {
  const [left, right] = address.toLowerCase().split('::');
  const before = left ? left.split(':') : [];
  const after = right ? right.split(':') : [];
  const parts = right === undefined ? before : [...before, ...Array(8 - before.length - after.length).fill('0'), ...after];
  return parts.reduce((number, part) => (number << 16n) + BigInt(`0x${part}`), 0n);
}

function ipv6In(address, prefix, bits) {
  const shift = BigInt(128 - bits);
  return (ipv6Number(address) >> shift) === (ipv6Number(prefix) >> shift);
}

function allowedAddress(address, policy) {
  const family = isIP(address);
  if (family === 4) {
    if (['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].some((entry) => {
      const [prefix, bits] = entry.split('/');
      return ipv4In(address, prefix, Number(bits));
    })) return true;
    if (policy !== 'public') return false;
    const blocked = ['0.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16', '192.0.0.0/24',
      '192.0.2.0/24', '192.88.99.0/24', '198.18.0.0/15', '198.51.100.0/24',
      '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '168.63.129.16/32'];
    return !blocked.some((entry) => {
      const [prefix, bits] = entry.split('/');
      return ipv4In(address, prefix, Number(bits));
    });
  }
  if (family !== 6 || address.includes('.') || address.includes('%')) return false;
  // IPv4-mapped, translation and transition addresses never bypass the IPv4 policy.
  if (ipv6In(address, '::ffff:0:0', 96) || ipv6In(address, '::', 96)) {
    return ipv6Number(address) === 1n;
  }
  // AWS's IPv6 metadata endpoint is within ULA space.
  if (ipv6Number(address) === ipv6Number('fd00:ec2::254')) return false;
  if (ipv6In(address, 'fc00::', 7)) return true;
  if (policy !== 'public' || !ipv6In(address, '2000::', 3)) return false;
  return ![['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]]
    .some(([prefix, bits]) => ipv6In(address, prefix, bits));
}

function parseUrl(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\\u0000-\u001f\u007f]/u.test(value)) {
    fail('URL must be a bounded HTTP(S) URL without whitespace or backslashes.');
  }
  const authority = value.match(/^https?:\/\/([^/?#]+)/iu)?.[1];
  if (!authority || authority.includes('@')) fail('Use an explicit HTTP(S) origin without user information.');
  let url;
  try { url = new URL(value); } catch { fail('Invalid target URL.'); }
  if (!['http:', 'https:'].includes(url.protocol)) fail('Only HTTP and HTTPS targets are allowed.');
  if (url.username || url.password || /[?#]/u.test(value)) fail('URL credentials, queries and fragments are not allowed.');
  if (!url.hostname || url.hostname.includes('%')) fail('Invalid target hostname.');
  return url;
}

function validatePolicy(networkPolicy) {
  if (!['private', 'public'].includes(networkPolicy)) fail('networkPolicy must be private or public.');
}

function checkDestination(url, blockedPorts, networkPolicy) {
  if (!Array.isArray(blockedPorts) || blockedPorts.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
    fail('blockedPorts must contain valid TCP port numbers.');
  }
  const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
  if (port < 1 || blockedPorts.includes(port)) fail(`Target port ${port} is blocked.`);
  const hostname = url.hostname.replace(/^\[|\]$/gu, '');
  if (isIP(hostname) && !allowedAddress(hostname, networkPolicy)) fail('Target address is outside the permitted network policy.');
  return hostname;
}

function checkPath(path, origin) {
  if (typeof path !== 'string' || path.length > 2048 || !path.startsWith('/') || path.startsWith('//') ||
    /[?#\\\s\u0000-\u001f\u007f]/u.test(path) || /%(?:0[0-9a-f]|1[0-9a-f]|7f|2f|5c)/iu.test(path) || /%(?![0-9a-f]{2})/iu.test(path)) {
    fail('Each path must be an exact absolute URL path without query, fragment, controls or encoded slashes.');
  }
  const parsed = new URL(path, origin);
  if (parsed.origin !== origin || parsed.pathname !== path) fail('Paths must already be URL-encoded and must not contain dot segments.');
}

export function validatePlan({ origin, paths, networkPolicy = 'private' } = {}, { blockedPorts = DEFAULT_BLOCKED_PORTS } = {}) {
  validatePolicy(networkPolicy);
  const url = parseUrl(origin);
  if (url.pathname !== '/' || !/^https?:\/\/[^/]+\/?$/iu.test(origin)) fail('Project origin must not contain a path.');
  checkDestination(url, blockedPorts, networkPolicy);
  if (!Array.isArray(paths) || paths.length < 1 || paths.length > MAX_PATHS) fail(`Provide 1 to ${MAX_PATHS} explicit paths.`);
  for (const path of paths) checkPath(path, url.origin);
  return { origin: url.origin, paths: [...new Set(paths)], networkPolicy };
}

function abortable(promise, signal) {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

export async function requestTarget(value, {
  signal,
  maxBytes = 262144,
  timeoutMs = 8000,
  blockedPorts = DEFAULT_BLOCKED_PORTS,
  networkPolicy = 'private',
  pinnedAddresses,
} = {}) {
  validatePolicy(networkPolicy);
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 2 * 1024 * 1024) fail('maxBytes must be between 1 and 2097152.');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) fail('timeoutMs must be between 1 and 60000.');
  const url = parseUrl(value);
  const rawPath = value.match(/^https?:\/\/[^/]+(\/.*)?$/iu)?.[1] || '/';
  checkPath(rawPath, url.origin);
  const hostname = checkDestination(url, blockedPorts, networkPolicy);
  const started = performance.now();
  const controller = new AbortController();
  const outerAbort = () => controller.abort(signal.reason || new Error('Request cancelled.'));
  if (signal?.aborted) outerAbort();
  else signal?.addEventListener('abort', outerAbort, { once: true });
  const timer = setTimeout(() => controller.abort(new Error(`Request timed out after ${timeoutMs} ms.`)), timeoutMs);
  try {
    controller.signal.throwIfAborted();
    const addresses = isIP(hostname)
      ? [{ address: hostname, family: isIP(hostname) }]
      : await abortable(dns.lookup(hostname, { all: true, verbatim: true }), controller.signal);
    if (addresses.length === 0 || addresses.some(({ address, family }) =>
      isIP(address) !== family || !allowedAddress(address, networkPolicy))) {
      fail('DNS returned an address outside the permitted network policy.');
    }
    controller.signal.throwIfAborted();
    // Validate every answer, then use exactly one pinned answer for this request.
    const resolvedAddresses = [...new Set(addresses.map(item => item.address))];
    if (pinnedAddresses && (pinnedAddresses.length !== resolvedAddresses.length || pinnedAddresses.some(address => !resolvedAddresses.includes(address)))) {
      fail('DNS addresses changed during this run. Review the target before starting a new run.');
    }
    const pinned = pinnedAddresses ? addresses.find(item => item.address === pinnedAddresses[0]) : addresses[0];
    return await new Promise((resolve, reject) => {
      let finished = false;
      const request = (url.protocol === 'https:' ? https : http).request(url, {
        method: 'GET',
        agent: false,
        family: pinned.family,
        autoSelectFamily: false,
        lookup: (_hostname, options, callback) => {
          if (options?.all) callback(null, [pinned]);
          else callback(null, pinned.address, pinned.family);
        },
        signal: controller.signal,
        rejectUnauthorized: true,
        maxHeaderSize: 16384,
        headers: { 'User-Agent': 'PenTri-Local/1.20', Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1', 'Accept-Encoding': 'identity', Connection: 'close' },
      }, (response) => {
        const chunks = [];
        let bytes = 0;
        const remoteAddress = response.socket?.remoteAddress || pinned.address;
        const complete = (truncated) => {
          if (finished) return;
          finished = true;
          const buffer = Buffer.concat(chunks, bytes);
          resolve({ url: url.href, status: response.statusCode, headers: { ...response.headers },
            body: buffer.toString('utf8'), bytes, truncated, resolvedAddresses,
            sha256: createHash('sha256').update(buffer).digest('hex'), remoteAddress,
            durationMs: Math.round(performance.now() - started) });
          if (truncated) { response.destroy(); request.destroy(); }
        };
        response.on('data', (chunk) => {
          if (finished) return;
          const remaining = maxBytes - bytes;
          const retained = chunk.subarray(0, remaining);
          if (retained.length) chunks.push(retained);
          bytes += retained.length;
          if (chunk.length > remaining) complete(true);
        });
        response.on('end', () => complete(false));
        response.on('error', (error) => {
          if (!finished) { finished = true; reject(controller.signal.aborted ? controller.signal.reason : error); }
        });
      });
      request.on('error', (error) => {
        if (!finished) { finished = true; reject(controller.signal.aborted ? controller.signal.reason : error); }
      });
      request.end();
    });
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', outerAbort);
  }
}
