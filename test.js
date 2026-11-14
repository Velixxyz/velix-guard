'use strict';
/**
 * test.js — local harness for VELIX Guard.
 * Spawns the server, runs live scans against real BNB Chain addresses,
 * and asserts the report shape. Requires network access to public BSC
 * RPC and Sourcify. Prints one line per case plus the verdict of each
 * live scan. Exit code 1 on any failure.
 */
const { spawn } = require('node:child_process');
const fs = require('node:fs');

const PORT = 3456;
const BASE = 'http://127.0.0.1:' + PORT;
let failures = 0;

function check(name, ok, extra) {
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (extra ? '  —  ' + extra : ''));
  if (!ok) failures += 1;
}

async function post(path, body) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep null */ }
  return { status: res.status, json, text };
}

async function main() {
  const server = spawn('node', ['server.js'], {
    cwd: __dirname,
    // NODE_USE_ENV_PROXY=1: this dev VM reaches the internet through an
    // egress proxy, and Node's fetch ignores proxy env vars without it.
    // Production (Vercel) has direct egress and needs no proxy setting.
    // Generous timeouts for this proxied dev VM (measured 6-14s per
    // upstream request). Production defaults in scan.js/server.js are
    // tighter and suit direct egress.
    env: { ...process.env, PORT: String(PORT), NODE_USE_ENV_PROXY: '1', RPC_TIMEOUT_MS: '15000', SOURCIFY_TIMEOUT_MS: '25000', SCAN_TIMEOUT_MS: '90000' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  server.stdout.on('data', (d) => { serverLog += d; });
  server.stderr.on('data', (d) => { serverLog += d; });

  // Wait for the health endpoint.
  let up = false;
  for (let i = 0; i < 30; i += 1) {
    try {
      const res = await fetch(BASE + '/health');
      if (res.ok) { up = true; break; }
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  check('server starts and /health answers', up);
  if (!up) {
    console.log(serverLog);
    server.kill();
    process.exit(1);
  }

  try {
    const health = await (await fetch(BASE + '/health')).json();
    check('health body', health.ok === true && health.service === 'velix-guard', JSON.stringify(health));

    const demo = await fetch(BASE + '/');
    const demoHtml = await demo.text();
    check('demo page serves HTML with scan form', demo.ok && demoHtml.includes('id="addr"') && demoHtml.includes('/scan'), demo.status + ' ' + demoHtml.length + ' bytes');

    const bad = await post('/scan', { address: 'not-an-address' });
    check('invalid address rejected with 400', bad.status === 400, JSON.stringify(bad.json));

    const cases = [
      { name: 'verified NFT (ONLYAI Crystals)', address: '0x156482AD3F0eebD8E3F70d494ebD1dA3F738f5Ba', expectVerified: true },
      { name: 'partial match NFT (Pocket Ai)', address: '0xf9D00B7a2992de00EBc5F9f04BAf95d44C542102', expectVerified: true },
      { name: 'verified NFT (CLAF Eye)', address: '0x1c759c4e075103b5b250db5114b832b17b99c456', expectVerified: true },
      { name: 'stablecoin (BSC USDT)', address: '0x55d398326f99059fF775485246999027B3197955', expectVerified: true },
      { name: 'dead address (no code)', address: '0x000000000000000000000000000000000000dEaD', expectVerdict: 'NOT_A_CONTRACT' },
    ];
    const reports = {};
    for (const c of cases) {
      const res = await post('/scan', { address: c.address });
      const r = res.json || {};
      const shapeOk = res.status === 200 && r.address && Array.isArray(r.findings) && typeof r.verdict === 'string' && typeof r.summary === 'string';
      check('scan shape: ' + c.name, shapeOk, res.status + ' verdict=' + r.verdict + ' risk=' + r.risk);
      if (shapeOk) {
        reports[c.name] = r;
        console.log('      sourcify=' + r.sourcify.status + ' proxy=' + r.isProxy + ' code=' + r.codeSize + 'B block=' + r.blockNumber + ' findings=' + r.findings.length + ' gaps=' + (r.dataGaps || []).join(','));
        console.log('      summary: ' + r.summary);
        if (c.expectVerified) {
          check('  verified on Sourcify: ' + c.name, r.sourcify.status === 'perfect' || r.sourcify.status === 'partial', 'status=' + r.sourcify.status);
        }
        if (c.expectVerdict) {
          check('  verdict: ' + c.name, r.verdict === c.expectVerdict, 'verdict=' + r.verdict);
        }
      }
    }

    // Approval mode: scan a token with a spender attached.
    const approval = await post('/scan', {
      address: '0x156482AD3F0eebD8E3F70d494ebD1dA3F738f5Ba',
      spender: '0x55d398326f99059fF775485246999027B3197955',
    });
    check('approval mode returns spender assessment', approval.status === 200 && approval.json && approval.json.approval && typeof approval.json.approval.advice === 'string',
      approval.status + ' spenderVerdict=' + (approval.json && approval.json.approval && approval.json.approval.spenderVerdict));

    fs.writeFileSync('/tmp/velix-guard-test-reports.json', JSON.stringify(reports, null, 2));
    console.log('Full reports saved to /tmp/velix-guard-test-reports.json');
  } finally {
    server.kill();
  }

  console.log(failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED');
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('harness error:', err);
  process.exit(1);
});
