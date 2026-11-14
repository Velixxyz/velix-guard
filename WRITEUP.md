# VELIX Guard — Wildcard submission write-up

Agent Games Wildcard track. Agent: VELIX Guard, a read-only
wallet/transaction guard for BNB Smart Chain.

## Use case

### The problem

The most common way people lose funds to a malicious contract is not a
hack of their wallet. It is a routine interaction they approved
themselves: an unlimited token approval to a spender they never checked,
a mint on a contract whose owner can rewrite the metadata the next day,
or a swap through a proxy whose logic gets upgraded after they looked at
it once. The information needed to catch these cases is public (bytecode
on chain, verified source on Sourcify, proxy slots, owner roles), but
checking it takes several tools and enough Solidity knowledge to read an
ABI. Most people skip the check.

### Who the agent helps

- Wallet users about to approve, mint, or swap on BNB Smart Chain.
- Agent operators whose agents interact with new contracts and need a
  machine-readable pre-flight screen before any signing step.
- Reviewers and researchers triaging many contracts quickly.

### What it actually does

Given a contract address, the agent reads live chain state and verified
source data and returns one structured report: whether code exists, the
current block, proxy status with the implementation address, token and
owner details, Sourcify verification status, and every privileged power
found in the verified ABI, each with its evidence. Given an optional
spender address, it scans the approval target too and returns
approval-specific advice (exact amount, throwaway wallet for first
contact, revoke afterwards). A demo page at the endpoint root lets anyone
run a scan in a browser with no tooling.

## Concept evaluation (why this agent)

Three concepts were evaluated against four criteria: real usefulness,
demonstrability through a public endpoint, shippable before the 21 Nov
close, and fit with work already proven in production.

| Concept | Useful | Demonstrable | Shippable | Proven fit | Verdict |
|---|---|---|---|---|---|
| **A. Wallet/transaction guard** (screen approvals and contracts) | High: prevents the most common self-approved loss | Yes: one POST returns a full report on any real address | Yes: read-only, keyless, zero deps | Direct: the same on-chain checks (verification, owner powers, proxy state) already run daily in screening work | **Chosen** |
| B. Research/reporting agent with citations | Medium: briefs are useful, but many already exist | Weak: needs an LLM key behind the endpoint, which is a secret to manage and a cost per call | Risky: key management + quality control in 7 days | Partial: research workflows exist, but not as a public endpoint | Rejected: secret + cost + weaker demo |
| C. Proof-decision auditor (re-check gatekeeper verdicts) | Low: meta-tool for one competition track, narrow audience | Yes, but only meaningful to other contestants | Yes | Strong, but the audience is tiny | Rejected: too narrow to be "a useful agent" |

Concept A won on every criterion. It is also the concept the Wildcard
page itself lists first among inspirations ("Wallet & transaction
guard"), and it is the only one of the three that is fully keyless: no
secret anywhere in the repo, the deployment, or the demo.

## Build context

### Architecture

One Node.js process, zero dependencies, plain `node:http`. Two files
carry the logic: `server.js` (HTTP service, demo page, rate limit,
timeouts) and `scan.js` (all chain and verifier reads plus the verdict
rules). The scan is stateless and deterministic given the same chain
state: the same address at the same block yields the same report.

### Key decisions

1. **Read-only, always.** The agent cannot sign, cannot hold a key, and
   cannot send a transaction. The worst failure mode is a wrong report,
   never a moved fund. This is a deliberate safety property, not a
   missing feature.
2. **Live data or an honest gap.** Every field comes from a live RPC or
   Sourcify read at scan time. When a source is unreachable, the report
   records a `dataGap` and the verdict becomes `UNKNOWN` instead of
   guessing. An unreachable verifier is never reported as "unverified":
   the two states mean different things, and conflating them would be a
   false statement about the contract.
3. **Fail closed on the verdict scale.** Unverified source yields
   `HIGH_RISK` with the wording "treat as untrusted until evidence proves
   otherwise", matching the screening rule that the absence of scam
   reports is not proof of cleanliness. A `CLEAR` verdict is only
   reachable with verified source and no privileged powers found.
4. **Findings cite evidence.** Each finding carries the exact function
   signature, slot value, or verifier status it came from, so a reader
   can re-check it without trusting the agent.
5. **Sourcify API v2.** API v1 was removed; v2 answers 404 with
   `{ match: null }` for unverified contracts, which the scanner treats
   as a real answer. One v2 call returns status, metadata, and ABI.
6. **Measured timeouts, not assumed ones.** Upstream latency was measured
   from the build environment (6-14s per request through a proxied
   network; racing all RPC endpoints at once made every request slower).
   The scanner uses serial endpoint fallback with generous, configurable
   timeouts, and the scan budget stays under the serverless function
   ceiling.
7. **The proven Vercel pattern, reused.** The sibling Proof Gatekeeper
   agent burned four deployments learning Vercel's serverless entrypoint
   rules (see the Creator Track article). This agent starts from the
   working pattern: bare handler export, `listen()` only when `VERCEL`
   is unset, `bodyParser: false`, `server.js` kept uploadable.
8. **Abuse containment.** 30 scans per IP per minute and a 64 KB body
   cap, because the upstream RPC and Sourcify endpoints are shared
   public goods and the endpoint is unauthenticated by design.

### What the agent can and cannot do

Can: screen any BNB Chain address in seconds; detect EIP-1967 proxies
and beacons; report verification status and compiler; enumerate
owner-controlled powers from verified ABIs; assess an approval spender;
serve a browser demo with no wallet connection.

Cannot: judge unverified bytecode at function level; detect sell-blocking
logic that only appears in execution traces; review the team, the
website, or off-chain promises; screen other chains; guarantee safety.
All of these limits are stated in the README and on the demo page.

## Verification evidence

- Local harness (`node test.js`, run 14 Nov 2026, ALL CHECKS PASSED):
  health, demo page, input validation, and live scans of real mainnet
  contracts: a verified NFT with owner powers (CAUTION, 7 findings
  including metadata-change and withdraw powers), a verified NFT with no
  privileged powers (CLEAR), a stablecoin (CLEAR), a no-code address
  (NOT_A_CONTRACT), and an approval-mode scan with spender assessment.
  Each scan names its block number, so the liveness of the reads is
  checkable.
- Vercel launcher simulation passed: the handler was required with
  `VERCEL=1` and invoked directly with mock requests, including a live
  scan through the launcher-provided body path.
- The demo page's example buttons scan real, well-known mainnet
  contracts, so a reviewer can reproduce a full report in one click
  with no address to find.

## zkVerify (optional verifiability plus)

No proof reference is claimed in v1, and none is faked. The checkable
claim a future version could add is precise: "this report describes the
bytecode at address A, whose code hash is H, as observed at block N."
That statement is re-checkable by anyone with chain access: fetch the
code at A at block N, hash it, compare. A zkVerify proof over that claim
would let a third party trust the report's freshness and provenance
without trusting the agent's server. The current report already carries
the three ingredients (address, block number, code size); a code hash
field and a proof pipeline are the remaining work, deliberately left out
of v1 rather than shipped half-proven.

## Links

- Repository: https://github.com/Velixxyz/velix-guard
- Public endpoint: https://velix-guard.vercel.app
- Demo: https://velix-guard.vercel.app/ — open the endpoint root in a browser.
