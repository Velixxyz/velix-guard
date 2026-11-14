'use strict';
/**
 * scan.js — read-only contract risk scan for BNB Smart Chain (chain 56).
 *
 * Data sources, all public and keyless:
 *   - Public BSC JSON-RPC: eth_getCode, eth_getStorageAt, eth_call, eth_blockNumber
 *   - Sourcify contract repository API v2: verification status + verified ABI
 *     (API v1 was removed; v2 answers 404 with { match: null } for
 *     unverified contracts, which is a real answer, not an error.)
 *
 * The scanner never signs, never sends a transaction, never holds a key,
 * and never needs a wallet. Every finding cites the evidence it came from.
 * Unverified code is reported as UNVERIFIED (behavior cannot be confirmed),
 * never as clean and never as proven malicious. Fail soft: when a source
 * is unreachable the report says so in `dataGaps` instead of guessing, and
 * an unreachable verifier yields UNKNOWN, not a false UNVERIFIED verdict.
 */

const RPC_URLS = [
  'https://bsc-dataseed.binance.org/',
  'https://bsc-dataseed1.defibit.io/',
  'https://bsc-dataseed1.ninicoin.io/',
  'https://bsc-dataseed2.defibit.io/',
];
const CHAIN_ID = 56;
const RPC_TIMEOUT_MS = parseInt(process.env.RPC_TIMEOUT_MS || '10000', 10);
const SOURCIFY_TIMEOUT_MS = parseInt(process.env.SOURCIFY_TIMEOUT_MS || '15000', 10);

// EIP-1967 slots.
const SLOT_IMPLEMENTATION = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const SLOT_BEACON = '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50';
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

const SELECTORS = {
  name: '0x06fdde03',
  symbol: '0x95d89b41',
  decimals: '0x313ce567',
  totalSupply: '0x18160ddd',
  owner: '0x8da5cb5b',
};

/**
 * Privileged-function name patterns, matched against verified ABIs only.
 * A match is a finding, not a verdict: many legitimate contracts have an
 * owner with withdraw or pause powers. The report states the power and
 * leaves the trust decision to the reader.
 */
const PRIVILEGED_PATTERNS = [
  { re: /^(withdraw|withdraweth|withdrawtoken|withdrawall|sweep|rescue|sweepeth|rescueeth|claimfees|withdrawfees|withdrawproceeds)$/i, severity: 'medium', title: 'Owner can withdraw funds', detail: 'An owner-only function can move ETH or tokens out of the contract.' },
  { re: /^(setbaseuri|settokenuri|seturi|setbaseextension|setmetadata|updateuri)$/i, severity: 'medium', title: 'Owner can change token metadata', detail: 'Token URIs or metadata can be replaced after mint, which can change what a token points to.' },
  { re: /^(mint|mintto|ownerMint|adminMint)$/i, severity: 'low', title: 'Privileged mint function', detail: 'New tokens can be minted by a privileged caller. Check who holds that role and whether supply is capped.' },
  { re: /^(pause|unpause|setpaused)$/i, severity: 'low', title: 'Pausable by a privileged caller', detail: 'Transfers or minting can be halted by the owner. A pause can freeze assets until lifted.' },
  { re: /^(blacklist|unblacklist|setblacklist|blocklist|excludefromfees|includeinfees)$/i, severity: 'medium', title: 'Owner can restrict addresses', detail: 'Specific addresses can be blocked or given fee exemptions, which can prevent selling.' },
  { re: /^(setfee|setfees|settax|settaxes|setbuyfee|setsellfee|setmax|setmaxtx|setmaxwallet|setmaxhold)$/i, severity: 'medium', title: 'Owner can change fees or limits', detail: 'Trading fees or per-wallet limits can be changed after launch, which can make selling expensive or impossible.' },
  { re: /^(upgradeto|upgradetoandcall|setimplementation|upgradeimplementation|setproxy)$/i, severity: 'high', title: 'Contract logic is upgradeable', detail: 'The implementation behind this address can be replaced. Current behavior does not guarantee future behavior.' },
  { re: /^(transferownership|renounceownership|setowner|transferadmin|setadmin)$/i, severity: 'info', title: 'Ownership can change hands', detail: 'Control of the contract can be transferred or renounced. Check the current owner.' },
  { re: /^(setminter|addminter|removeminter|grantrole|revokerole|settreasury|setrouter|setpair|enabletrading|settrading)$/i, severity: 'low', title: 'Privileged configuration function', detail: 'A privileged caller can change roles, treasury, router, or trading state.' },
  { re: /^(selfdestruct|kill|destroy)$/i, severity: 'high', title: 'Contract can be destroyed', detail: 'A selfdestruct path exists. Treat with extreme caution.' },
];

function isAddress(value) {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value.trim());
}

function normalizeAddress(value) {
  return '0x' + value.trim().slice(2).toLowerCase();
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

async function rpcCall(method, params) {
  // Serial fallback across endpoints. Racing all endpoints at once was
  // measured to hurt on proxied networks (16 concurrent requests all
  // slowed to ~14s); the scan already parallelizes across calls, so one
  // attempt per call keeps concurrency low and the first healthy
  // endpoint usually answers in 1-3s.
  let lastError = null;
  for (const url of RPC_URLS) {
    try {
      const res = await fetchWithTimeout(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      }, RPC_TIMEOUT_MS);
      if (!res.ok) throw new Error('HTTP ' + res.status + ' from ' + url);
      const json = await res.json();
      if (json.error) throw new Error(json.error.message || 'RPC error');
      return json.result;
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error('all RPC endpoints failed');
}

function hexToBigInt(hex) {
  if (typeof hex !== 'string' || !/^0x[0-9a-fA-F]*$/.test(hex)) return null;
  try { return BigInt(hex); } catch { return null; }
}

function decodeCallString(hex) {
  // ABI-encoded string (offset + length + data) or a bare bytes32.
  if (typeof hex !== 'string' || !hex.startsWith('0x')) return null;
  const body = hex.slice(2);
  if (body.length >= 128) {
    const len = hexToBigInt('0x' + body.slice(64, 128));
    if (len !== null && len <= BigInt(10000)) {
      const n = Number(len);
      const raw = body.slice(128, 128 + n * 2);
      try {
        const text = Buffer.from(raw, 'hex').toString('utf8').replace(/\0+$/, '');
        if (text.length > 0 && /^[\x20-\x7E\u00A0-\uFFFF]*$/.test(text)) return text;
      } catch { /* fall through */ }
    }
  }
  if (body.length === 64) {
    try {
      const text = Buffer.from(body, 'hex').toString('utf8').replace(/\0+$/, '');
      if (text.length > 0 && /^[\x20-\x7E]*$/.test(text)) return text;
    } catch { /* fall through */ }
  }
  return null;
}

function decodeCallAddress(hex) {
  if (typeof hex !== 'string' || hex.length < 42) return null;
  const addr = '0x' + hex.slice(-40).toLowerCase();
  return isAddress(addr) ? addr : null;
}

async function ethCall(to, data) {
  try {
    const result = await rpcCall('eth_call', [{ to, data }, 'latest']);
    return result;
  } catch {
    return null; // A revert or missing function is normal for view probes.
  }
}

/**
 * One Sourcify v2 call returns status + metadata + ABI.
 * Returns { status: 'perfect'|'partial'|null, abi, contractName, compiler }.
 * A 404 with { match: null } means genuinely unverified (status null, no
 * throw). Network errors, timeouts, and 5xx throw, so the caller can
 * record a data gap instead of a false UNVERIFIED verdict.
 */
async function fetchSourcifyContract(address) {
  const url = 'https://sourcify.dev/server/v2/contract/' + CHAIN_ID + '/' + address + '?fields=metadata,abi';
  const res = await fetchWithTimeout(url, { headers: { accept: 'application/json' } }, SOURCIFY_TIMEOUT_MS);
  if (res.status === 404) {
    return { status: null, match: null, abi: null, contractName: null, compiler: null };
  }
  if (!res.ok) throw new Error('Sourcify v2 HTTP ' + res.status);
  const data = await res.json();
  const match = data && typeof data.match === 'string' ? data.match : null;
  // v2 vocabulary varies by verification age: newer entries use
  // exact_match/partial_match, older ones use match/partial. Both "match"
  // forms mean the deployed bytecode matches verified source.
  const status = match === 'exact_match' || match === 'match' ? 'perfect'
    : match === 'partial_match' || match === 'partial' ? 'partial' : null;
  const metadata = data && data.metadata && typeof data.metadata === 'object' ? data.metadata : null;
  let abi = null;
  if (metadata && metadata.output && Array.isArray(metadata.output.abi)) abi = metadata.output.abi;
  else if (Array.isArray(data.abi)) abi = data.abi;
  let contractName = null;
  try {
    const targets = metadata && metadata.settings && metadata.settings.compilationTarget
      ? Object.values(metadata.settings.compilationTarget) : [];
    contractName = targets[0] || null;
  } catch { /* ignore */ }
  const compiler = metadata && metadata.compiler && metadata.compiler.version ? String(metadata.compiler.version) : null;
  return { status, match, abi, contractName, compiler };
}

function analyzeAbi(abi) {
  const findings = [];
  const functions = abi.filter((e) => e && e.type === 'function' && typeof e.name === 'string');
  const names = new Set(functions.map((f) => f.name.toLowerCase()));
  const seen = new Set();

  for (const fn of functions) {
    const sig = fn.name + '(' + (fn.inputs || []).map((i) => i.type).join(',') + ')';
    for (const pattern of PRIVILEGED_PATTERNS) {
      if (!pattern.re.test(fn.name)) continue;
      const key = pattern.title + '|' + fn.name;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: 'abi.' + fn.name.toLowerCase(),
        severity: pattern.severity,
        title: pattern.title,
        evidence: 'verified ABI function ' + sig + ' (' + (fn.stateMutability || 'unknown') + ')',
        detail: pattern.detail,
      });
    }
  }

  const hasReceive = abi.some((e) => e && e.type === 'receive');
  const hasFallback = abi.some((e) => e && e.type === 'fallback');
  if (hasReceive || hasFallback) {
    findings.push({
      id: 'abi.payable-entrypoint',
      severity: 'info',
      title: 'Contract can receive ETH directly',
      evidence: hasReceive ? 'verified ABI has a receive() entrypoint' : 'verified ABI has a fallback entrypoint',
      detail: 'Plain ETH transfers to this contract will succeed. That alone is not a risk signal.',
    });
  }

  const standard =
    names.has('ownerof') && names.has('tokenuri') ? 'ERC-721 (likely)' :
    names.has('transfer') && names.has('approve') && names.has('balanceof') ? 'ERC-20 (likely)' :
    names.has('uri') && names.has('safetransferfrom') ? 'ERC-1155 (likely)' : null;

  return { findings, standard, functionCount: functions.length };
}

function computeVerdict(report) {
  if (report.codeSize === 0) {
    return {
      verdict: 'NOT_A_CONTRACT',
      risk: 'high',
      summary: 'This address holds no contract code. If you expected a contract, the address is wrong or the contract no longer exists.',
    };
  }
  if (report.dataGaps.includes('rpc')) {
    return {
      verdict: 'UNKNOWN',
      risk: 'unknown',
      summary: 'On-chain data could not be read, so this report cannot judge the contract. Retry later; do not treat the absence of findings as safety.',
    };
  }
  // Verifier unreachable is UNKNOWN, not UNVERIFIED: the status is unknown,
  // and claiming "unverified" would be a false statement about the contract.
  if (report.sourcify.status === null && report.dataGaps.includes('sourcify')) {
    return {
      verdict: 'UNKNOWN',
      risk: 'unknown',
      summary: 'Verification status could not be checked (Sourcify unreachable), so this report cannot confirm or deny that the source is verified. Retry later.',
    };
  }
  if (report.sourcify.status === null) {
    return {
      verdict: 'HIGH_RISK',
      risk: 'high',
      summary: 'Source code is unverified, so the contract behavior cannot be confirmed from source. Treat as untrusted until evidence proves otherwise.',
    };
  }
  const severities = report.findings.map((f) => f.severity);
  if (severities.includes('high')) {
    return {
      verdict: 'HIGH_RISK',
      risk: 'high',
      summary: 'Verified source, but high-severity privileged powers were found. Read every finding before interacting.',
    };
  }
  if (severities.includes('medium')) {
    return {
      verdict: 'CAUTION',
      risk: 'medium',
      summary: 'Verified source with owner-controlled powers that could change behavior or move funds. Check who holds the owner role.',
    };
  }
  if (report.dataGaps.includes('sourcify-metadata')) {
    return {
      verdict: 'CAUTION',
      risk: 'medium',
      summary: 'Verified source, but the ABI could not be fetched, so owner powers were not enumerated. Treat the finding list as incomplete.',
    };
  }
  if (report.isProxy) {
    return {
      verdict: 'CAUTION',
      risk: 'medium',
      summary: 'Verified proxy contract. The logic behind it can change, so re-scan before each interaction.',
    };
  }
  return {
    verdict: 'CLEAR',
    risk: 'low',
    summary: 'Verified source, no privileged powers found in the ABI. This is a code screen, not a guarantee: it says nothing about the team, the website, or off-chain promises.',
  };
}

/**
 * Scan one contract address. Options: { spender } also scans an approval
 * target and adds approval-specific findings.
 */
async function scanContract(rawAddress, options = {}) {
  const address = normalizeAddress(rawAddress);
  const dataGaps = [];
  const findings = [];
  const report = {
    address,
    chainId: CHAIN_ID,
    chainName: 'BNB Smart Chain',
    scannedAt: new Date().toISOString(),
    blockNumber: null,
    codeSize: null,
    isProxy: false,
    implementation: null,
    beacon: null,
    sourcify: { status: null, match: null, contractName: null, compiler: null },
    token: { name: null, symbol: null, decimals: null, totalSupply: null, standard: null },
    owner: null,
    findings,
    dataGaps,
    sources: ['bsc public json-rpc', 'sourcify.dev api v2'],
  };

  // 1. On-chain reads.
  let code = null;
  try {
    const [codeRes, blockRes, implSlot, beaconSlot] = await Promise.all([
      rpcCall('eth_getCode', [address, 'latest']),
      rpcCall('eth_blockNumber', []),
      rpcCall('eth_getStorageAt', [address, SLOT_IMPLEMENTATION, 'latest']),
      rpcCall('eth_getStorageAt', [address, SLOT_BEACON, 'latest']),
    ]);
    code = codeRes;
    const blockNum = hexToBigInt(blockRes);
    report.blockNumber = blockNum !== null ? Number(blockNum) : null;
    const impl = decodeCallAddress(implSlot);
    const beacon = decodeCallAddress(beaconSlot);
    if (impl && impl !== ZERO_ADDRESS) {
      report.isProxy = true;
      report.implementation = impl;
      findings.push({
        id: 'proxy.eip1967',
        severity: 'medium',
        title: 'Proxy contract (EIP-1967)',
        evidence: 'implementation slot holds ' + impl,
        detail: 'Calls are delegated to the implementation contract. The implementation can be upgraded, so behavior can change after this scan.',
      });
    }
    if (beacon && beacon !== ZERO_ADDRESS) {
      report.isProxy = true;
      report.beacon = beacon;
      findings.push({
        id: 'proxy.beacon',
        severity: 'medium',
        title: 'Beacon proxy (EIP-1967)',
        evidence: 'beacon slot holds ' + beacon,
        detail: 'The implementation is resolved through a beacon contract that can be updated.',
      });
    }
  } catch (err) {
    dataGaps.push('rpc');
    findings.push({
      id: 'data.rpc-unreachable',
      severity: 'info',
      title: 'On-chain data unreachable',
      evidence: 'all public BSC RPC endpoints failed: ' + String(err.message || err).slice(0, 120),
      detail: 'The scan could not read chain state. Nothing below should be read as a clean bill of health.',
    });
  }

  if (typeof code === 'string') {
    report.codeSize = code === '0x' ? 0 : Math.max(0, (code.length - 2) / 2);
  }

  // No code: nothing further to inspect.
  if (report.codeSize === 0) {
    const verdict = computeVerdict(report);
    return { ...report, ...verdict };
  }

  // 2. View-function probes (best effort; reverts are normal).
  if (!dataGaps.includes('rpc')) {
    const [nameRes, symbolRes, decimalsRes, supplyRes, ownerRes] = await Promise.all([
      ethCall(address, SELECTORS.name),
      ethCall(address, SELECTORS.symbol),
      ethCall(address, SELECTORS.decimals),
      ethCall(address, SELECTORS.totalSupply),
      ethCall(address, SELECTORS.owner),
    ]);
    report.token.name = decodeCallString(nameRes);
    report.token.symbol = decodeCallString(symbolRes);
    const dec = hexToBigInt(decimalsRes);
    report.token.decimals = dec !== null ? Number(dec) : null;
    const supply = hexToBigInt(supplyRes);
    report.token.totalSupply = supply !== null ? supply.toString() : null;
    report.owner = decodeCallAddress(ownerRes);
    if (report.owner && report.owner !== ZERO_ADDRESS) {
      findings.push({
        id: 'owner.present',
        severity: 'info',
        title: 'Contract has an owner role',
        evidence: 'owner() returns ' + report.owner,
        detail: 'Whoever controls this address can call owner-only functions listed below.',
      });
    }
  }

  // 3. Sourcify v2 verification + ABI analysis (one call).
  try {
    const verified = await fetchSourcifyContract(address);
    report.sourcify.status = verified.status; // 'perfect' | 'partial' | null
    report.sourcify.match = verified.match; // raw Sourcify v2 match value
    report.sourcify.contractName = verified.contractName;
    report.sourcify.compiler = verified.compiler;
    if (verified.status === null) {
      findings.push({
        id: 'sourcify.unverified',
        severity: 'high',
        title: 'Source code unverified on Sourcify',
        evidence: 'Sourcify v2 returned no match for chain 56',
        detail: 'No verified source exists, so function-level behavior cannot be confirmed. Bytecode-only review would be needed for a deeper check.',
      });
    } else {
      findings.push({
        id: 'sourcify.verified',
        severity: 'info',
        title: 'Source code verified on Sourcify (' + verified.status + ' match)',
        evidence: 'Sourcify v2 match: ' + (verified.match || verified.status),
        detail: verified.status === 'partial'
          ? 'Partial match: the deployed bytecode matches the source except for metadata. Function analysis below still applies.'
          : 'Exact match: the deployed bytecode matches the verified source.',
      });
      if (verified.abi) {
        const analysis = analyzeAbi(verified.abi);
        report.token.standard = analysis.standard;
        findings.push(...analysis.findings);
      } else {
        dataGaps.push('sourcify-metadata');
        findings.push({
          id: 'sourcify.abi-unavailable',
          severity: 'info',
          title: 'Verified source found, but the ABI could not be fetched',
          evidence: 'Sourcify v2 response carried no usable ABI',
          detail: 'Function-level findings are missing from this report. The contract is verified, but its powers were not enumerated.',
        });
      }
    }
  } catch (err) {
    dataGaps.push('sourcify');
    findings.push({
      id: 'data.sourcify-unreachable',
      severity: 'info',
      title: 'Sourcify unreachable',
      evidence: 'verification lookup failed: ' + String(err.message || err).slice(0, 120),
      detail: 'Verification status is unknown for this scan. Retry later before trusting the contract.',
    });
  }

  // 4. Optional approval-target scan.
  if (options.spender && isAddress(options.spender)) {
    const spenderAddress = normalizeAddress(options.spender);
    const spenderReport = await scanContract(spenderAddress);
    report.approval = {
      spender: spenderAddress,
      spenderVerdict: spenderReport.verdict,
      spenderRisk: spenderReport.risk,
      spenderVerified: spenderReport.sourcify.status,
      spenderIsProxy: spenderReport.isProxy,
      advice: spenderReport.verdict === 'CLEAR'
        ? 'The spender contract is verified with no privileged powers found. Still approve only the amount you need, and revoke when done.'
        : spenderReport.verdict === 'NOT_A_CONTRACT'
          ? 'The spender is not a contract. Approving a plain address gives that address direct control over the approved amount.'
          : 'The spender is unverified, proxied, or has privileged powers. Do not grant unlimited approval. Approve the exact amount, use a throwaway wallet for first interaction, and revoke afterwards.',
    };
  }

  const verdict = computeVerdict(report);
  return { ...report, ...verdict };
}

module.exports = { scanContract, isAddress, normalizeAddress, CHAIN_ID };
