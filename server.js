'use strict';
/**
 * server.js — VELIX Guard: a read-only wallet/transaction guard agent.
 *
 * POST /scan { address, spender? } -> a structured risk report for a BNB
 * Smart Chain contract, built from live on-chain reads and Sourcify
 * verification data. No keys, no wallet, no signing, no paid services.
 *
 * GET / serves a small demo page that calls the same endpoint, so anyone
 * can watch the agent work on a real address without writing a request.
 *
 * Deployment pattern (proven by the sibling Proof Gatekeeper agent on
 * Vercel, 14 Nov 2026): this file exports the bare request handler and
 * calls listen() ONLY when the VERCEL env var is unset. Exporting
 * `{ server }` crashes every Vercel invocation, and listen() at module
 * load hangs every request; the handler export + conditional listen
 * avoids both failure modes.
 */
const http = require('node:http');
const { scanContract, isAddress } = require('./scan');

const _PORT = parseInt(process.env.PORT || '3000', 10);
const PORT = Number.isFinite(_PORT) && _PORT > 0 ? _PORT : 3000;
const MAX_BODY_BYTES = 64 * 1024;
const SCAN_TIMEOUT_MS = parseInt(process.env.SCAN_TIMEOUT_MS || '45000', 10);

// Tiny in-memory rate limit: 30 scans per IP per minute. The endpoint is
// read-only, but upstream RPC and Sourcify are shared public goods.
const RATE_LIMIT = 30;
const RATE_WINDOW_MS = 60 * 1000;
const rateBuckets = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const bucket = rateBuckets.get(ip);
  if (!bucket || now >= bucket.resetAt) {
    rateBuckets.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return false;
  }
  bucket.count += 1;
  if (rateBuckets.size > 10000) rateBuckets.clear();
  return bucket.count > RATE_LIMIT;
}

function log(obj) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...obj }));
}

function sendJson(res, statusCode, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(statusCode, {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    'cache-control': 'no-store',
  });
  res.end(body);
}

function readRawBody(req) {
  // Same Vercel-launcher quirk as the gatekeeper: the launcher may hand
  // us a body it already read. Prefer a byte-exact req.body, else read
  // the stream ourselves.
  if (Buffer.isBuffer(req.body)) return Promise.resolve(req.body);
  if (req.body !== undefined && req.body !== null && typeof req.body !== 'object') {
    return Promise.resolve(Buffer.from(String(req.body), 'utf8'));
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('scan timed out after ' + ms + 'ms')), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

const DEMO_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VELIX Guard — read-only contract screen (BNB Chain)</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#111;line-height:1.5}
code{background:#f1f1f1;padding:0 .3em;border-radius:4px}
input{width:100%;padding:.6rem;font-size:1rem;margin:.2rem 0 .8rem;box-sizing:border-box}
button{padding:.6rem 1.2rem;font-size:1rem;cursor:pointer}
pre{background:#0d1117;color:#e6edf3;padding:1rem;border-radius:8px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.badge{display:inline-block;padding:.1rem .6rem;border-radius:999px;font-weight:600}
.high{background:#fde2e2}.medium{background:#fff3cd}.low{background:#d9ead3}.unknown{background:#e2e3e5}
.ex{margin:.4rem .4rem 0 0}
small{color:#555}
</style></head><body>
<h1>VELIX Guard</h1>
<p>A read-only agent that screens a BNB Smart Chain contract <em>before</em> you interact with it: live bytecode and proxy checks, Sourcify verification, and the owner-controlled powers found in the verified ABI. It never signs, never holds a key, and never sends a transaction.</p>
<label>Contract address<br><input id="addr" placeholder="0x..." spellcheck="false"></label>
<label>Approval spender (optional)<br><input id="spender" placeholder="0x... (address you are about to approve)"></label>
<button id="go">Scan</button>
<span id="status"></span>
<div>
<button class="ex" data-a="0x156482AD3F0eebD8E3F70d494ebD1dA3F738f5Ba">Example: verified NFT</button>
<button class="ex" data-a="0xf9D00B7a2992de00EBc5F9f04BAf95d44C542102">Example: partial match</button>
<button class="ex" data-a="0x55d398326f99059fF775485246999027B3197955">Example: stablecoin</button>
</div>
<h2>Report</h2>
<div id="verdict"></div>
<pre id="out">No scan yet. Paste a contract address and press Scan.</pre>
<h2>API</h2>
<p><code>POST /scan</code> with JSON <code>{"address": "0x...", "spender": "0x..."}</code>. Response is the same report object shown above. <code>GET /health</code> returns service status.</p>
<p><small>Limits: this is a code screen, not a guarantee. It says nothing about the team, the website, or off-chain promises. Unverified code is reported as unverified, never as clean. BNB Smart Chain only.</small></p>
<script>
const out = document.getElementById('out');
const verdict = document.getElementById('verdict');
const status = document.getElementById('status');
document.querySelectorAll('.ex').forEach(b => b.addEventListener('click', () => {
  document.getElementById('addr').value = b.dataset.a;
}));
document.getElementById('go').addEventListener('click', async () => {
  const address = document.getElementById('addr').value.trim();
  const spender = document.getElementById('spender').value.trim();
  status.textContent = 'Scanning live chain data...';
  out.textContent = '';
  verdict.innerHTML = '';
  try {
    const res = await fetch('/scan', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(spender ? { address, spender } : { address }) });
    const report = await res.json();
    status.textContent = res.ok ? ('Done in block ' + (report.blockNumber || 'unknown')) : ('Error ' + res.status);
    if (res.ok) {
      verdict.innerHTML = '<span class="badge ' + report.risk + '">' + report.verdict + ' / risk: ' + report.risk + '</span> ' + report.summary;
    }
    out.textContent = JSON.stringify(report, null, 2);
  } catch (e) {
    status.textContent = 'Request failed: ' + e.message;
  }
});
</script>
</body></html>`;

async function handleRequest(req, res) {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'content-type',
      });
      res.end();
      return;
    }

    if (req.method === 'GET' && (path === '/' || path === '/index.html')) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(DEMO_PAGE);
      return;
    }

    if (req.method === 'GET' && (path === '/health' || path === '/api' || path === '/api/index')) {
      res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
      res.end(JSON.stringify({ ok: true, service: 'velix-guard', chainId: 56, time: new Date().toISOString() }));
      return;
    }

    if (req.method === 'POST' && path === '/scan') {
      const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').toString().split(',')[0].trim();
      if (rateLimited(ip)) {
        sendJson(res, 429, { error: 'rate limited: 30 scans per minute per IP' });
        return;
      }
      let rawBody;
      try {
        rawBody = await readRawBody(req);
      } catch {
        sendJson(res, 413, { error: 'request body too large' });
        return;
      }
      let body;
      try {
        body = JSON.parse(rawBody.toString('utf8'));
      } catch {
        sendJson(res, 400, { error: 'invalid JSON body' });
        return;
      }
      if (!body || typeof body !== 'object' || !isAddress(body.address)) {
        sendJson(res, 400, { error: 'address is required and must be a 0x-prefixed 40-hex-character address' });
        return;
      }
      if (body.spender !== undefined && body.spender !== null && body.spender !== '' && !isAddress(body.spender)) {
        sendJson(res, 400, { error: 'spender, when provided, must be a 0x-prefixed 40-hex-character address' });
        return;
      }
      const started = Date.now();
      try {
        const report = await withTimeout(
          scanContract(body.address, body.spender ? { spender: body.spender } : {}),
          SCAN_TIMEOUT_MS);
        log({ scan: body.address, verdict: report.verdict, risk: report.risk, ms: Date.now() - started });
        sendJson(res, 200, report);
      } catch (err) {
        log({ level: 'error', scan: body.address, error: String(err.message).slice(0, 200), ms: Date.now() - started });
        sendJson(res, 502, {
          error: 'scan failed: upstream chain or verification data unreachable',
          detail: String(err.message).slice(0, 200),
          address: body.address,
        });
      }
      return;
    }

    sendJson(res, 404, { error: 'not found', usage: 'POST /scan {"address":"0x..."} or open GET / for the demo page' });
  } catch (err) {
    log({ level: 'error', msg: 'unhandled request error', error: String(err.message).slice(0, 200) });
    try { sendJson(res, 500, { error: 'internal error' }); } catch { /* socket gone */ }
  }
}

const server = http.createServer(handleRequest);

// Listen ONLY outside Vercel. On Vercel the launcher invokes the exported
// handler directly per request; listen() at module load hangs every
// request (proven by the sibling gatekeeper agent, deployment d54ebcd).
if (!process.env.VERCEL) {
  server.listen(PORT, () => {
    log({ msg: 'listening', port: PORT, service: 'velix-guard' });
  });
}

module.exports = handleRequest;
module.exports.config = { api: { bodyParser: false } };
