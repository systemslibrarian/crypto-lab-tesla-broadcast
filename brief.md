# Build brief — `crypto-lab-tesla-broadcast`

**2026-10-20. Brief only; no repository exists yet.** Written against
`audits/_MASTER-TEMPLATE.md` (catalog `20cb434d89e4`) — §0 through §6 apply unchanged.
Source of the gap: Boneh–Shoup v0.6 §14.7 ("A fun application: the TESLA broadcast MAC"),
with §14.3 (Definition 14.5, one-way on iterates) and Exercise 14.21.

**Verdict: new repository.**

```
NEW DEMO BRIEF
- Repo name:         crypto-lab-tesla-broadcast
- Short name (H1):   TESLA Broadcast
- Subtitle:          Timed broadcast authentication · RFC 4082 · delayed key disclosure
- One-liner:         A broadcaster MACs each interval's messages with HMAC-SHA-256 under a key
                     from a one-way SHA/HMAC key chain, reveals that key one or more intervals
                     later, and anchors the chain with one Ed25519 signature; receivers
                     authenticate with cheap MACs and a timing rule.
- Concept to teach:  A MAC can authenticate a broadcast to receivers who cannot forge — but
                     only because of TIME: a packet is safe exactly when the receiver can prove
                     its key was still secret when the packet was sent. Get the clock bound
                     wrong and every cryptographic check passes on a forgery.
- Primitives/spec:   RFC 4082 §3.2–3.5 (key chain F, MAC-key derivation F', packet format,
                     safe-packet test); Perrig–Canetti–Tygar–Song, IEEE S&P 2000; Boneh–Shoup
                     v0.6 §14.7 and Remark 14.1; HMAC-SHA-256 (RFC 2104, KATs RFC 4231) via
                     WebCrypto; SHA-256 (FIPS 180-4) via WebCrypto; Ed25519 (RFC 8032) via
                     @noble/curves for the chain anchor
- Accent (--accent): [central assignment]
- Favicon emoji:     [central assignment]
- Category:          [central assignment]
- Level (suggested): Intermediate (Act 0 and Act 1 readable by a Beginner)
- Section (suggested): key-exchange ("Key Exchange & Protocols")
- In scope:          key-chain generation and verification (RFC 4082 F and F'); sender and
                     receiver with simulated clocks; the RFC 4082 §3.5 safe-packet test with
                     interval length T_int, disclosure delay d and the receiver's lag bound D_t;
                     packet loss and forward hashing; a spoofer who replays disclosed keys; the
                     shared-key-MAC failure; signature-vs-TESLA bandwidth at 20 bits/s (B–S
                     §14.7); tag truncation and measured guessing forgeries; an OSNMA card
- Non-goals:         OSNMA conformance (message formats, DSM-KROOT, MACK, ADKD) — extension
                     seam only; Remark 14.1's per-chain nonce and position input (one-line
                     note); µTESLA / multi-level chains; the Exercise 14.21 no-delay variant;
                     real radio, real time sync protocols, real networks
```

## Overlap check — what I read, and what I found

Searched every clone in `/home/claude/labs` (`*.ts *.html *.md *.js`, excluding node_modules,
.git, dist) for `\bTESLA\b|osnma|galileo|gnss|delayed (key )?disclosure|key disclosure|broadcast
auth|loss.?tolerant|multicast (source )?auth`. Hits inspected:

- `crypto-lab-lattice-fault/src/main.ts:550` names "TESLA" — the lattice signature scheme of
  that name in a list of ePrint 2016/449 targets. Unrelated.
- `crypto-lab-shelf-oracle` (`fb27f8bbd4ed`) `src/data/catalog.ts:77` — "Galileo Galilei" as a
  library-book author. Unrelated.
- `crypto-lab-time-lock-puzzle` README/index use "delayed disclosure" for time-lock escrow, not
  broadcast authentication.
- Remaining "disclosure" hits are `<details>` disclosure widgets in e2e files.

Neighbours opened (commit pinned), and how this lab differs:

- **Time Trust** (`1578c9763ac5`) is the closest neighbour. Its thesis — "time is an
  unauthenticated input to authenticated systems" — and its design invariant at
  `src/time/clock.ts:1–5` ("Every verifier in the lab takes a clock VALUE as an argument — no
  module ever reads Date.now()") are exactly right for this lab. Adopt that invariant (write
  your own clock module; do not import across repos). Time Trust shows a clock lie flipping a
  verdict on a certificate, JWT or TOTP. This lab shows the other direction: a protocol whose
  security PROOF depends on a stated clock bound, and the exact inequality where it fails.
  Cross-link both ways.
- **Pulse Chain** (`2dc17f8647a4`): hash-chained public randomness beacons (NIST Beacon pulses
  chained by SHA-512; drand rounds). A forward chain of published values, not a one-way chain of
  secrets disclosed in reverse. Link as "a different job for a hash chain".
- **LMS Ledger** (`4b3e43e894ff`, `src/lms.ts:146`, Winternitz chain visualiser at
  `src/main.ts:65`) and **SPHINCS+ Ledger** (`d218fb257cb6`): Winternitz hash chains inside
  one-time signatures — B–S §14.3, the same "one-way on iterates" property (Definition 14.5)
  this lab relies on. Link both.
- **MAC Race** (`bc4f683362e4`): MAC comparison; no broadcast setting. Act 1 here is the reason a
  plain MAC does not solve broadcast — link to MAC Race for HMAC itself.
- **Signed Bytes** (`8ab85f3e2dd4`): signatures over bytes. Link for the anchor signature.

The agent re-runs the grep above before building and reports anything new.

## The seven §1 sections

### SCOPE

0. **What is this.** Plain language, no maths: a satellite has to prove every second that its
   message is real, but it can only spare a few bits, and millions of receivers must be able to
   check it without being able to fake it. TESLA's trick is a secret it gives away *later*.
1. **One key for everyone fails.** Three receivers share one HMAC key with the broadcaster.
   Receiver 2 (the learner) writes a fake message, tags it with the shared key, and Receiver 1's
   real HMAC check accepts it. Verdict: "VALID TAG — AND FORGED BY A RECEIVER" (ALARM). Then the
   signature fix and its cost: B–S §14.7's framing — 20 bits/s available for authentication; a
   384-bit signature takes 19.2 s per message (show the arithmetic from the inputs).
2. **The key chain.** Generate a chain of n keys (n ≤ 4096) per RFC 4082 §3.2: random K_N,
   K_i = F(K_{i+1}), commitment K_0 signed with Ed25519. Step through it. The learner picks a
   disclosed key K_i and the page verifies it back to the anchor by hashing forward i times.
   Drop packets (a loss slider): a later key still authenticates every buffered packet from the
   lost intervals, because F^j(K_i) reaches the last authenticated key. Show the hash count.
3. **The timing rule (headline mechanism).** A timeline of sender intervals of length T_int with
   disclosure delay d. Each packet P_j = {M_j ‖ i ‖ MAC(K'_i, M_j) ‖ K_{i−d}} (RFC 4082 §3.4).
   The receiver's clock lags the sender's by δ (learner-controlled, the TRUE value); the receiver
   believes the lag is at most D_t (learner-controlled, the ASSUMED bound). On arrival at local
   time T the receiver computes x = ⌊(T + D_t − T_0)/T_int⌋ and accepts the packet as *safe* only
   if x < i + d (RFC 4082 §3.5 step 1); safe packets wait for K_i, then are verified.
   - A spoofer listens, captures K_i the moment it is disclosed, writes a fake message for
     interval i, tags it with the real K'_i and delivers it at once.
   - **Break it yourself:** move D_t below δ. The forged packet now passes the safe-packet test,
     the disclosed key verifies to the anchor, the MAC verifies, and the receiver accepts a
     forgery: "AUTHENTICATED — AND FORGED". Move D_t back to ≥ δ and the same forged bytes are
     discarded as unsafe. Derivation to show on the page (zero network delay for the spoofer,
     which is the spoofer's best case): the forgery arrives at sender time
     T_0 + (i+d)·T_int, so x = ⌊i + d + (D_t − δ)/T_int⌋, and x < i + d exactly when D_t < δ.
   - **The trade-off:** a D_t much larger than δ makes the receiver discard *genuine* late
     packets (count them). Too small is insecure, too large is unavailable.
   - **B–S preset.** B–S §14.7 states its design with d = 1, slot-tagged messages, and clock skew
     at most T/2. Load that preset and let the sweep show where it holds under the lab's broadcast
     timing. *Note for the agent:* the book does not say where in the slot each broadcast goes
     out; the T/2 bound works if each broadcast leaves at the middle of its slot. State the timing
     the lab models, and do not claim the book's bound for any other placement without the sweep
     showing it.
4. **Bits on the air.** Per-interval authentication data = tag bits + key bits. Inputs: tag
   length t, key length k, channel rate. Show B–S §14.7's own figures recomputed from the inputs:
   32 + 128 = 160 bits → 8 s at 20 bits/s; 20 + 100 = 120 bits → 6 s. Then truncation as an
   attack surface: with t = 8, the learner fires 10,000 random-tag forgeries at the real verifier
   and the page counts acceptances against the predicted 10,000/2^8 (show a confidence interval).
5. **Where this runs: Galileo OSNMA.** A prose card, every fact cited:
   - Galileo's Open Service Navigation Message Authentication "adapts an existing standard
     lightweight broadcast authentication protocol named TESLA" (GSC page).
   - OSNMA Initial Service was declared operational on 24 July 2025 (GSC page).
   - From the Receiver Guidelines (Issue 1.3, January 2024): tags are HMAC-SHA-256 or CMAC-AES
     (§5.5.5, Table 8); chain hash SHA-256 or SHA3-256 (§5.4.3, Table 6); sub-frames are 30 s and
     a tag is verified with the key broadcast in the next sub-frame (§5.3.2, §5.5.4); the time
     synchronisation requirement T_L is 30 s, with |GST_SIS − GST_Rx| < T_L/2 for standard
     processing (§2.1, §5.3.1 Eq. 1); the Annex A test configuration uses 40-bit tags and 128-bit
     keys (Annex A.2).
   - Say plainly: "This lab implements TESLA as RFC 4082 describes it. It does not implement
     OSNMA's message formats and is not an OSNMA receiver."

Non-goal notes in-page, one line each:
- OSNMA formats: "a deployed adaptation, described on this page, not implemented".
- Remark 14.1: "real chains also feed a per-chain nonce and the key's position into f, to block
  precomputation; this lab's chain does not".
- Exercise 14.21: "a variant with no authentication delay exists, at the cost of longer tags".
- µTESLA / multi-level chains: future extension.

### SECURITY / CORRECTNESS INVARIANTS

1. **Time is an input.** No protocol module reads `Date.now()` or `performance.now()`. Every
   sender, receiver and spoofer decision takes a simulated clock value (Time Trust's invariant).
2. **Bootstrap first.** No key is used until the Ed25519 signature on K_0 (and the parameters
   T_0, T_int, d, n it commits to) verifies (RFC 4082 §2.2).
3. **Safe-packet test before buffering.** A packet that fails x < i + d is discarded at arrival
   and never MAC-verified later, even after its key arrives.
4. **Key before MAC.** A MAC is checked only with K'_i = F'(K_i) where K_i has been hashed
   forward to an already-authenticated key. A key that does not chain is rejected and named.
5. **Chain key ≠ MAC key.** K'_i = F'(K_i), never K_i itself (RFC 4082 §3.4).
6. **The broken settings are isolated.** "Assumed bound below true lag" and "skip the safe-packet
   test" live in `src/attack/`, are never the default, and are visibly marked broken whenever
   active. The default state has D_t ≥ δ.
7. **Real results only.** Every verdict comes from a real WebCrypto HMAC or SHA-256 call and a
   real Ed25519 verification. No verdict is computed from the slider positions alone.
8. **Ranges are enforced.** Interval index i ∈ [1, n]; tag length t ∈ [8, 256] bits in whole
   bytes; d ≥ 1; T_int > 0. Out-of-range values are refused with the reason.

### ARCHITECTURE

```
src/crypto/hmac.ts        WebCrypto HMAC-SHA-256 (sign/verify, truncation helper)
src/crypto/sha256.ts      WebCrypto SHA-256 (KAT target)
src/crypto/anchor.ts      Ed25519 sign/verify of the commitment (@noble/curves)
src/tesla/chain.ts        F(k) = HMAC(k, 0x00), F'(k) = HMAC(k, 0x01); chain build; verifyToAnchor
src/tesla/packet.ts       encode/decode P_j = {M ‖ i ‖ tag ‖ K_{i−d}}; strict parser
src/tesla/sender.ts       interval schedule from T_0, T_int, d; packet emission
src/tesla/receiver.ts     safe-packet test, buffer, key authentication, MAC check, loss handling
src/tesla/time.ts         simulated clocks: sender time, receiver lag δ, assumed bound D_t
src/attack/spoofer.ts     captures disclosed keys, forges packets (isolated)
src/attack/shared-key.ts  Act 1's shared-key forgery (isolated)
src/bandwidth.ts          bits/delay arithmetic and the truncation-guessing experiment
src/ui/*                  one module per act
```

F and F' as written above are this lab's choice of PRF (HMAC-SHA-256 with one-byte inputs 0 and
1, matching RFC 4082 §3.2/§3.4's f_k(0) and f'_k(1) shape). Say on the page that RFC 4082 names a
pseudo-random function, not a specific one, and that OSNMA uses its own functions (Act 5).
Hand-roll the chain, packet, schedule and receiver logic — they are what is taught. HMAC, SHA-256
and Ed25519 come from WebCrypto and @noble/curves.

### UI

- **Act 3 is the core interaction.** Two sliders, labelled by what they are: "True clock lag δ
  (what is actually happening)" and "Assumed lag bound D_t (what the receiver believes)", plus
  T_int and d selectors. A horizontal timeline of sender intervals; disclosure points marked; the
  receiver's local clock drawn as an offset track. One button: "Spoof interval i". The packet
  animates once to the receiver; each check lights in order — safe-packet test, key chains to
  anchor, MAC — with icon, text and colour.
- Act 2: chain stepper with a hash counter and a loss slider; dropped packets greyed with a
  "lost" label (never colour alone).
- Act 4: inputs t, k, rate; computed delay; the guessing experiment with a running count.
- Stacks below 640px. Every long run (Act 4 experiment) is cancellable; changing an input retires
  the old verdict with "retired: inputs changed".

### VISUAL SEMANTICS

- Colour tracks the receiver's actual security, not a check's return value. A forged packet that
  every check accepted reads **ALARM**: "AUTHENTICATED — AND FORGED".
- A forged packet discarded by the safe-packet test reads as the system holding ("REJECTED:
  key may already be public").
- A genuine packet discarded because D_t is too large reads WARN (availability, not security).
- Always icon + text + colour; check grayscale and deuteranopia.

### EDGE CASES

| Input | Behaviour |
|---|---|
| Anchor signature does not verify | nothing proceeds; "bootstrap failed" with the reason |
| Disclosed key does not hash to an authenticated key within n steps | rejected, packet stays unauthenticated |
| Packet for interval i arrives after K_i was already received | discarded by the safe-packet test |
| Duplicate packet | the second copy is ignored and counted |
| All packets in a run of intervals lost | later key hashes forward across the gap; count shown |
| D_t < 0 or T_int ≤ 0 or d < 1 | refused with the reason |
| Tag length not a whole number of bytes, or < 8 bits | refused |
| Chain exhausted (i > n) | "chain exhausted: a new anchor is needed" |
| Input changed mid-experiment | cancelled; old verdict retired |

### EXTENSION SEAMS

- `// [extension] point` in `src/tesla/chain.ts`: Remark 14.1's hardened chain
  k_i = f(k_{i−1}, N, i), and OSNMA's chain functions.
- `// [extension] point` in `src/tesla/packet.ts`: an OSNMA conformance mode pinned to the official
  test vectors (see Tests — the vectors exist; the formats are not implemented here).
- `// [extension] point` in `src/tesla/receiver.ts`: multi-level chains / µTESLA, and the
  Exercise 14.21 immediate-authentication variant.

## Tests

**KATs (Vitest), all against WebCrypto / @noble/curves through the lab's own wrappers:**
- HMAC-SHA-256: RFC 4231 Test Cases 1–7. Test Case 6 (131-byte key of 0xaa, data "Test Using
  Larger Than Block-Size Key - Hash Key First" → `60e43159…0ee37f54`) and Test Case 7 (131-byte
  key, data longer than one 64-byte block → `9b09ffa7…3a35e2`) exceed one block. Test Case 5 is
  a truncated-output case — use it for the truncation helper.
- SHA-256: NIST CSRC "Examples with Intermediate Values" SHA256.pdf — "abc" (one block) and the
  56-byte "abcdbcdecdef…nopq" message, which takes two blocks after padding → `248D6A61 D20638B8
  E5C02693 0C3E6039 A33CE459 64FF2167 F6ECEDD4 19DB06C1`.
- Ed25519: RFC 8032 §7.1 TEST 1, 2, 3 and **TEST 1024 (1023-byte message, longer than one
  128-byte SHA-512 block)**.
- RFC 4082 publishes no test vectors that I found; the agent confirms by reading the RFC, and the
  chain is tested by independent re-derivation instead.

**Unit tests:**
- chain: F^i(K_i) = K_0 for every i; tampered key rejected; F' ≠ identity on every key.
- the timing theorem as a property test: over a grid of (δ, D_t, T_int, d), the spoofer's
  packet is accepted iff D_t < δ; genuine packets are accepted iff their arrival satisfies the
  test (compute both from the formula in the test file, independently of `receiver.ts`).
- loss: random loss patterns never cause a wrong acceptance; every non-lost genuine packet is
  eventually authenticated when a later key arrives.
- import-list test: `src/tesla/*` imports nothing from `src/attack/*`.

**`e2e/claims.spec.ts` (§4.1b):**
- Act 3: parse δ, D_t, T_int, d, i and the arrival time from the rendered row; recompute x and the
  safe test in the test; assert the rendered verdict matches. Re-verify the MAC in the test with
  Node's `crypto.createHmac` on the bytes the page displays.
- Act 2: parse the displayed disclosed key and the anchor; hash forward in the test with Node
  crypto; assert the page's hop count.
- Act 4: recompute (t + k)/rate from the inputs; assert 8 s and 6 s for the B–S presets; assert
  the acceptance count is consistent with the binomial interval shown.
- Act 1: re-verify the forged tag with the displayed shared key.
- retirement on input change, and the no-op guard.

**§4.1c mutations, one per rendered verdict** (in a script, per the template's verdict-marker
rule):
- safe test uses `x <= i + d`;
- receiver skips key-to-anchor hashing;
- F' replaced by identity (MAC key = chain key);
- spoofer delivery time computed one interval late (the forgery would never be accepted);
- Act 4 delay divides by the wrong rate;
- Act 1 verifier checks a different key.

**§4.1d negative claims, scoped to this construction:**
- **Fixture A.** "TESLA's authentication depends on the receiver's clock bound; with a wrong
  bound, every check passes on a forgery." Setup: Act 3 with D_t < δ. Every rendered check is
  green (anchor signature, key chains to anchor, MAC verifies, safe-packet test passes as
  computed), and the message is the spoofer's. Verdict: "AUTHENTICATED — AND FORGED".
- **Fixture B.** "A TESLA tag is not evidence to a third party." After K_i is disclosed, the
  learner (as anyone) computes a valid tag for any message in interval i; an offline checker
  given the transcript and the disclosed key accepts it. Verdict: "TAG VERIFIES — AND ANYONE
  COULD HAVE MADE IT". (No non-repudiation; contrast with the Ed25519-signed anchor.)

## Honesty notes for the page

- Real HMAC-SHA-256, SHA-256 and Ed25519; simulated clocks, radio and network.
- Toy chain lengths and intervals; real OSNMA parameters are cited, not reproduced.
- The security of TESLA also assumes the MAC stays secure for K_i even given F(K_i) (B–S §14.7)
  and that F is one-way on n iterates (B–S Definition 14.5); this lab assumes them, it does not
  test them.
- "Not production crypto — a teaching demo."

## Links out

Time Trust (time as an unauthenticated input) · Pulse Chain (hash-chained beacons) · LMS Ledger
and SPHINCS+ Ledger (one-way hash chains in signatures) · MAC Race (HMAC) · Signed Bytes
(signatures).

## Sources (verified 2026-10-20)

- D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*, v0.6, Jan. 2023,
  https://toc.cryptobook.us/ — §14.7, Remark 14.1, Definition 14.5, Exercise 14.21 (read in the
  book text).
- A. Perrig, D. Song, R. Canetti, J. D. Tygar, B. Briscoe, "Timed Efficient Stream Loss-Tolerant
  Authentication (TESLA): Multicast Source Authentication Transform Introduction," RFC 4082,
  June 2005, Informational — https://www.rfc-editor.org/rfc/rfc4082 (§2.2, §3.2–3.5 read).
- A. Perrig, R. Canetti, J. D. Tygar, D. Song, "Efficient Authentication and Signing of Multicast
  Streams over Lossy Channels," Proc. 2000 IEEE Symposium on Security and Privacy, May 2000,
  pp. 56–73 — https://people.eecs.berkeley.edu/~tygar/papers/Efficient_authentication_signing_multicast.pdf
- European GNSS Service Centre, "Galileo Open Service Navigation Message Authentication (OSNMA)"
  — https://www.gsc-europa.eu/node/7200 (TESLA adaptation; Initial Service declared 24 July 2025;
  current documents Receiver Guidelines v1.3 and IDD/ICD v1.1).
- EUSPA, *Galileo OSNMA Receiver Guidelines*, Issue 1.3, January 2024 —
  https://www.euspa.europa.eu/sites/default/files/2024-03/Galileo_OSNMA_Receiver_Guidelines_v1.3.pdf
  (§2.1, §5.3.1 Eq. 1, §5.4.3 Table 6, §5.5.5 Table 8, Annex A.2).
- OSNMA test vectors: published as "Annex B – OSNMA Test Vectors" (Test_vectors.zip) with
  Receiver Guidelines v1.1 — https://www.gsc-europa.eu/node/7493; that page said TESLA chain
  management vectors were planned for later updates. For the extension seam only.
- M. Nystrom, RFC 4231, December 2005 — https://www.rfc-editor.org/rfc/rfc4231 (Test Cases 6, 7
  checked).
- NIST CSRC, SHA256.pdf (Examples with Intermediate Values) —
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
- S. Josefsson, I. Liusvaara, RFC 8032, January 2017 — https://www.rfc-editor.org/rfc/rfc8032
  (§7.1, TEST 1024 is 1023 bytes).
