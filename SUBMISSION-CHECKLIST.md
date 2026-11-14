# Wildcard submission checklist — VELIX Guard

Competition closes 21 Nov 2026; judging 22-30 Nov. This file tracks the
dashboard submission. Do NOT submit until every MUST item is green.

## Package status (14 Nov 2026)

- [x] Agent built and tested locally: `server.js`, `scan.js`, `api/index.js`
- [x] Demo page at GET / with working example scans
- [x] Write-up: `WRITEUP.md` (use case, build context, limits, zkVerify note)
- [x] README with API docs, deploy steps, honest limitations
- [x] No secrets anywhere in the package (no keys, no wallet, no tokens)
- [x] Local harness `test.js` — see "Test evidence" below
- [ ] MUST: public GitHub repo created (see "Needs lokie" below)
- [ ] MUST: code pushed to the repo
- [ ] MUST: public HTTPS endpoint deployed + probe-verified (see "Needs lokie")
- [ ] MUST: repo URL + endpoint URL filled into `WRITEUP.md` Links section
- [ ] MUST: dashboard submission form completed (mechanism unverified — see below)

## Test evidence (local harness, 14 Nov 2026)

Run: `node test.js` from this directory. Live scans against BNB Chain
mainnet through public RPC + Sourcify v2. Final run: ALL CHECKS PASSED.

| Case | Result |
|---|---|
| Server start + GET /health | 200, `{ok, service: velix-guard, chainId: 56}` |
| GET / demo page | 200, HTML with scan form |
| POST /scan invalid address | 400 with clear error |
| ONLYAI Crystals NFT | 200, CAUTION, Sourcify perfect, 7 findings (mint, setBaseURI, withdrawProceeds, ownership) |
| Pocket Ai NFT | 200, CAUTION, Sourcify perfect, 6 findings |
| CLAF Eye NFT | 200, CLEAR, Sourcify perfect, 5 findings |
| BSC USDT | 200, CLEAR, Sourcify perfect, 5 findings |
| Dead address (no code) | 200, NOT_A_CONTRACT |
| Approval mode (token + spender) | 200, spender assessment + advice |

Vercel launcher simulation (require with `VERCEL=1`, invoke the exported
handler with mock req/res, including a live scan through the
launcher-provided Buffer body path): PASSED. No `listen()` at load,
bare function export, `bodyParser: false`.

Bugs found and fixed by this testing: Sourcify API v1 is removed (v2
only); v2 `match` values include the older `"match"` vocabulary, which
first mapped to a false UNVERIFIED; an unreachable verifier first
yielded a false UNVERIFIED verdict instead of UNKNOWN; racing all RPC
endpoints at once slowed every request on proxied networks (serial
fallback now).

Local git: one commit (`5a1e0fc`) with remote
`https://github.com/Velixxyz/velix-guard.git` preconfigured (repo does
not exist yet; see item 1 below).

## Dashboard form fields (from the public Wildcard page)

| Field | Value |
|---|---|
| Agent link | Public repo URL (pending) |
| Public endpoint | Public HTTPS endpoint URL (pending) |
| Use case | `WRITEUP.md` "Use case" section |
| Build context | `WRITEUP.md` "Build context" section |
| zkVerify | `WRITEUP.md` "zkVerify" section (optional plus; no proof reference claimed) |

## Needs lokie (decisions / dashboard actions)

1. **Create the GitHub repo.** The GitHub connector cannot create repos:
   an attempt on 14 Nov 2026 (approved, via the connector's
   `create_repository`) failed with `403 Resource not accessible by
   integration`, matching the known App-token limit. Do not retry it.
   Lokie creates a PUBLIC repo named `velix-guard` on github.com (no
   README/license/gitignore from GitHub's templates — the package brings
   its own files), then grants the Muse GitHub App access to it (repo
   selection in the installation settings). After that, the code can be
   pushed from here (local commit `5a1e0fc` is ready; remote already
   points at the expected URL).
2. **Deploy to Vercel.** The Vercel MCP connector is not connected, so no
   deploy can run from here. Lokie: Vercel dashboard → Add New Project →
   Import `velix-guard` → Deploy. No environment variables needed. Then
   share the deployment URL so the endpoint can be probe-verified
   (GET /health 200, POST /scan 200 on a real address) before submission.
   Alternative: connect Vercel OAuth in Muse settings, then a deploy can
   be attempted from here.
3. **Confirm the submission mechanism.** The public Wildcard page says a
   submission form asks for the repo, endpoint, use case, and build
   context, but the exact form location and deadline behavior were not
   verified live. Verify in the dashboard before 21 Nov; if the form
   needs anything beyond the fields above, say so and the package will
   be extended.

## What was NOT done (by design)

- No dashboard form submitted (handled separately).
- No post published anywhere (Creator Track drafts are drafts only).
- No wallet action, no paid service, no secret created or stored.
