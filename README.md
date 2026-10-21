# TESLA Broadcast

## What It Is

Implements an RFC 4082-style one-way HMAC-SHA-256 key chain, distinct MAC keys, an Ed25519-signed anchor, receiver safety check, and delayed-key broadcast authentication. Simulated sender and receiver clocks make the timing assumption inspectable. Not production crypto — a teaching demo. All material is generated in memory; this static site has no account, backend or key storage.

## Exhibits

1. Forge a shared-key MAC as one of its receivers.
2. Build a signed chain and verify a later disclosed key after dropped intermediate packets.
3. Set the true receiver clock lag and its assumed upper bound; spoof a packet after key disclosure and watch the real checks in order.
4. Calculate radio airtime and run 10,000 random truncated-tag guesses.
5. Read the sourced Galileo OSNMA adaptation note, with no OSNMA parsing or conformance claim.

## When to Use It

Use this to study the exact mechanism and its failure boundary. Do not use the toy implementation, keys or protocols in a deployed security system.

## Live Demo

[Open TESLA Broadcast](https://systemslibrarian.github.io/crypto-lab-tesla-broadcast/) to drive the exhibits. The build uses Vite's `/crypto-lab-tesla-broadcast/` base for GitHub Pages.

## What Can Go Wrong

If the receiver assumes a lag smaller than its true lag, a packet forged after disclosure passes the safety test, key-chain verification and real MAC verification. The valid tag does not prove authorship to a third party after disclosure.

## Real-World Usage

Galileo OSNMA adapts TESLA, but this code does not implement its formats, authentication messages or receiver rules. Sender and receiver clocks and the network are simulated; signatures, MACs and hashes are real.

## How to Run Locally

```sh
npm ci
npm run dev
```

## Related Demos

[Time Trust](https://github.com/systemslibrarian/crypto-lab-time-trust) · [Pulse Chain](https://github.com/systemslibrarian/crypto-lab-pulse-chain) · [MAC Race](https://github.com/systemslibrarian/crypto-lab-mac-race) · [Signed Bytes](https://github.com/systemslibrarian/crypto-lab-signed-bytes)

## Build & Verify

```sh
npm test
npm run build
npx playwright install chromium
npm run test:a11y
npm run test:mutations
```

6 unit tests including RFC 4231 HMAC, NIST SHA-256 and RFC 8032 Ed25519 vectors, plus a grid of timing-bound attack outcomes and rejection ordering. The RFC defines protocol logic rather than publishing a TESLA KAT. The replayable mutation harness contains 4 concrete source patches. Each run first passes its named baseline test, requires a non-empty diff, a successful build and changed JavaScript bundle hash, then requires the owning test to fail and restores the original hash. The Playwright suite scans reachable desktop and mobile states for WCAG 2.1 A/AA issues and independently rederives displayed claims. GitHub Actions runs unit tests, production build and browser gate before deploying; it also gates Dependabot pull requests, groups minor/patch npm updates and dispatches a deploy after an automated merge.

## Performance

All runs are local to the browser. Work figures shown in the page are either actual counted operations or explicitly labelled mathematical estimates/extrapolations. Workers keep long searches cancellable where used. No speed number is a claim about a production deployment.

## Sources

- [RFC 4082 §§2.2, 3.2–3.5](https://www.rfc-editor.org/rfc/rfc4082)
- [Boneh–Shoup v0.6 §14.7](https://toc.cryptobook.us/)
- [Galileo OSNMA Receiver Guidelines 1.3](https://www.euspa.europa.eu/sites/default/files/2024-03/Galileo_OSNMA_Receiver_Guidelines_v1.3.pdf)

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
