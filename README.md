# VELIX Guard — a read-only wallet/transaction guard agent

An agent that screens a BNB Smart Chain contract **before** you interact
with it: live bytecode and proxy checks, Sourcify verification, and the
owner-controlled powers found in the verified ABI. It never signs, never
holds a key, never sends a transaction, and needs no API keys.

Built as a Wildcard entry for the zkVerify Agent Games. A sibling agent
(VELIX-1, Proof Gatekeeper track) runs the same deployment pattern in
production.

## Who it helps

Anyone about to approve a token, mint an NFT, or interact with a contract
they have not reviewed: the guard answers, in seconds and with cited
evidence, whether the contract's source is verified, whether it is a
proxy whose logic can change, and which privileged powers the owner holds.
The recurring real-world failure it targets is the unlimited approval (or
the mint, or the swap) granted to an unverified or owner-controlled
contract that later drains, freezes, or rewrites what the user thought
they owned.

## What it checks (live data, every scan)

| Check | Source |
|---|---|
| Contract code exists, and its size | `eth_getCode` (public BSC RPC) |
| Proxy detection (EIP-1967 implementation + beacon slots) | `eth_getStorageAt` |
| Current block (proves the read is live) | `eth_blockNumber` |
| Token name, symbol, decimals, total supply, owner | `eth_call` view probes |
| Source verification status (exact / partial / none) | Sourcify API v2 |
| Privileged functions in the verified ABI (withdraw, metadata changes, mint, pause, blacklist, fee changes, upgrades, ownership) | Sourcify verified metadata |
| Approval target assessment (optional `spender`) | A second full scan of the spender |

Verdicts: `CLEAR`, `CAUTION`, `HIGH_RISK`, `UNKNOWN` (a source was
unreachable, so the report refuses to judge), `NOT_A_CONTRACT`. Unverified
source is reported as unverified, never as clean and never as proven
malicious. Every finding cites its evidence.

## API

```sh
# Health
curl https://<deployment>/health

# Scan a contract
curl -X POST https://<deployment>/scan \
  -H 'content-type: application/json' \
  -d '{"address": "0x156482AD3F0eebD8E3F70d494ebD1dA3F738f5Ba"}'

# Scan a contract plus the address you are about to approve
curl -X POST https://<deployment>/scan \
  -H 'content-type: application/json' \
  -d '{"address": "0x...", "spender": "0x..."}'
```

`GET /` serves a small demo page that calls the same endpoint, so anyone
can watch the agent work without writing a request.

Rate limit: 30 scans per IP per minute (the upstream RPC and Sourcify
endpoints are shared public goods). Request bodies are capped at 64 KB.

## Run locally

```sh
node server.js   # listens on $PORT (default 3000); no dependencies, no build
```

```sh
node test.js     # local harness: health, demo page, validation, and live
                 # scans of real mainnet contracts (needs internet)
```

Environment knobs (all optional): `PORT`, `RPC_TIMEOUT_MS` (default
10000), `SOURCIFY_TIMEOUT_MS` (default 15000), `SCAN_TIMEOUT_MS` (default
45000). On networks behind an egress proxy, Node's `fetch` needs
`NODE_USE_ENV_PROXY=1` to honor proxy variables; production on Vercel has
direct egress and needs no proxy setting.

## Deploy (Vercel)

1. Push this repo to GitHub.
2. In Vercel: Add New Project, import the repo, Deploy. No environment
   variables are needed: the agent uses only public, keyless endpoints.
3. Check `https://<project>.vercel.app/health` and open `/` for the demo
   page. No redeploy is needed after deploy: there is no per-deployment
   configuration to freeze.

Deployment pattern (proven by the sibling gatekeeper agent, 14 Nov 2026):
`server.js` exports the bare request handler and calls `listen()` only
when `VERCEL` is unset. `api/index.js` re-exports the same handler as a
fallback. `.vercelignore` must keep `server.js`, `scan.js`, and `api/`
uploadable; only `test.js` is excluded.

## Honest limitations

- **BNB Smart Chain only.** Other chains need their own RPC + verifier
  wiring; the scanner refuses to guess across chains.
- **Verified ABI only.** For unverified contracts the guard can report
  code size, proxy status, and view-function probes, but not
  function-level powers. Bytecode-only analysis is out of scope.
- **Name-pattern matching.** Privileged powers are found by function-name
  patterns in the ABI. Unusual names can evade a pattern, and a matched
  name does not prove the function is reachable by a malicious owner.
  The report states the power and leaves the trust decision to the
  reader; it is a screen, not an audit.
- **No team, website, or off-chain review.** A `CLEAR` verdict says
  nothing about who runs the project, whether the website is genuine, or
  whether off-chain promises will be kept.
- **Point-in-time.** A proxy's implementation can be upgraded after a
  scan. Re-scan before each interaction.
- **No honeypot simulation.** The guard does not simulate buy/sell
  transactions, so it cannot detect sell-blocking logic that only shows
  up in execution traces.

## Security notes

- No secrets exist in this project: no keys, no wallet, no API tokens.
  Nothing is signed, and nothing is ever sent to a chain.
- No user data is stored. Scans are stateless; the only in-memory state
  is the per-IP rate-limit bucket.
- The demo page makes no wallet connection and asks for no signature.

## Files

```
server.js            HTTP service (plain node:http, no framework, no deps)
scan.js              pure scanning logic: RPC + Sourcify v2 + verdict rules
api/index.js         Vercel function fallback (re-exports the handler)
test.js              local harness (live mainnet scans, not shipped)
vercel.json          function maxDuration 60s
```

## zkVerify note

No zero-knowledge proof is claimed for this agent's reports in v1. The
checkable claim a future version could add is: "this report describes the
bytecode at address A with code hash H as observed at block N" — a
statement a verifier could re-check against the chain without trusting
the agent. That integration is described, not faked, in `WRITEUP.md`.
