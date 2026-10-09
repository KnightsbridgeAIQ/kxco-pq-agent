# Changelog

## 1.4.0 (2026-10-09)

Runtime support. No change to the API or its behaviour.

**Node.js 22.12 or later is required.** `engines.node` moves from `>=20.19`
to `>=22.12`. Node 20 reached end of life on 30 April 2026. 22.12 is the
first Node 22 release that loads ES modules through `require()` without a
flag, the same property the 20.19 floor provided.

**Releases are built on Node 26**, where they were built on Node 22.
Node 26 ships npm 11.20, which already carries Trusted Publishing, so the
release job no longer downloads npm 11 separately.

## 1.3.0 (2026-10-07)

**ML-DSA-87 is the default for a new agent key.** `KxcoAgentIdentity.create()`
without `alg` now generates an ML-DSA-87 keypair: a 2592-byte public key and
4627-byte signatures, per FIPS 204. Such an agent signs relay intents over
`kxco-relay-agent-v1.1` with `alg: ML-DSA-87` in the intent, as an ML-DSA-87
agent already did in 1.2.0.

To keep the old behaviour, pass `alg: 'ML-DSA-65'` to `create()`. That agent
gets an ML-DSA-65 key and signs `kxco-relay-agent-v1` exactly as before.

Existing keys are unaffected. An agent created or exported before 1.3.0 keeps
its ML-DSA-65 key, and the key decides the set it signs with. A credential with
no `sponsorAlg` is still read as ML-DSA-65, and a sponsor that exposes no key and
no `alg` is still read as ML-DSA-65, so every credential already issued verifies
unchanged. The sponsor's set is always its own key's and is not changed by this
release.

## 1.2.1

Documentation. No source change.

The package description, the opening of the README and the keywords now say
what 1.2.0 already does: an agent's key, and its sponsor's, can each be
ML-DSA-87 as well as ML-DSA-65. `ml-dsa-87` joins the keywords.

## 1.2.0
**ML-DSA-87 agents and sponsors.** `KxcoAgentIdentity.create({ alg: 'ML-DSA-87' })`
gives the agent an ML-DSA-87 key, and `agent.alg` reports the set; ML-DSA-65
stays the default. The sponsor's set is read from its key (`publicKeyHex` or
`getPublicKey()`), or from `sponsor.alg` when it exposes neither; a stated alg
that disagrees with the key, or a signature of the other set, is refused at
creation.

**The algorithm travels with the signature.** An ML-DSA-87 sponsor's credential
carries `sponsorAlg: 'ML-DSA-87'` and is signed over
`kxco-agent-credential-v1.1`, whose second line is the algorithm. An ML-DSA-87
agent signs relay intents over `kxco-relay-agent-v1.1`, with `alg: ML-DSA-87`
after the first line, and sends `alg` in the intent. ML-DSA-65 credentials and
intents keep exactly the v1 shape and bytes.

**The key decides on verification.** `KxcoAgentIdentity.verify` verifies under the
sponsor key's set and refuses a credential whose `sponsorAlg` names the other
set. A credential with no `sponsorAlg` is read as ML-DSA-65, and a test verifies
an agent exported by 1.1.1.

The `kxco-post-quantum` floor is now ^1.6.0.

## 1.1.1

checkScope denies an amount, spentToday or limit that is not a finite number,
and any section, limit or `enabled` switch of the wrong type, naming it.
validateScope requires positive integer limits, string recipients and boolean
`enabled` switches. verify() and import() validate the scope they return, and
verify() treats an expiresAt that is not a date as expired. A scope key named
`__proto__` is refused.

Credential text fields and relay intent header fields must be one line of
well-formed text, and AgentChainClient refuses a relay that is not a string.
The typings now say that an empty purposes list allows no purpose.

**The npm page leads with what the package proves.** The first screen now says
who answers for an agent, what it may do and how both ends enforce it, the
evidence underneath and the migration dates set by NIST, Executive Order 14412,
OMB M-26-15 and the UK NCSC.

A family table maps every KXCO package to the job it does, and a new For
institutions section sets out the operated services and how to reach us. The
evidence documents are unchanged and linked from the page.

The scope manifest example uses a complete recipient address, so it validates
as written, and the page gains Security, Release integrity and License sections.

A NOTICE file names the copyright owner, Knightsbridge Financial Ltd, trading
as KXCO, and ships in the package, so anyone who redistributes it carries the
attribution, as section 4(d) of the Apache License requires.

## 1.1.0

**`checkScope()` enforces the scope locally, before the relay sees the action.**

```js
import { checkScope } from 'kxco-pq-agent'

const decision = checkScope(agent.scope, {
  type: 'payment', amount: 4500, spentToday: 12000, recipient: '0xAbC…',
})
// { allowed: false,
//   reason: "amount 4500 would take today's total to 16500, past maxPerDay 15000",
//   checked: ['payments.enabled', 'payments.maxPerTransaction', 'payments.maxPerDay'] }
```

The relay's enforcement is unchanged and is still the one that binds, because it
sits behind the agent where a compromised agent cannot reach it. This runs in
front, on the same signed scope, and earns its place three ways: it refuses
offline, so an agent that cannot reach the relay still knows what it may not do;
it refuses without spending a round trip; and it names the limit that stopped
it, which a remote refusal cannot do as precisely.

**Fails closed throughout.** A capability the scope does not grant is denied. An
action type it does not recognise is denied. A configured limit that cannot be
judged from the inputs given is denied rather than skipped — pass a scope with
`maxPerDay` set and no `spentToday`, and the answer is a refusal that says which
input is missing, not a pass that quietly skipped a control.

`checked` reports every limit the decision actually evaluated, in the order
applied, so a caller can show the control ran rather than assert it did.

Covers payments (`maxPerTransaction`, `maxPerDay`, `allowedRecipients`, with EVM
recipients matched case-insensitively), attestation purposes, `auditLog` and
`credentials`. Eleven tests.

**ASSESSMENT.md rewritten** to lead with the containment properties — an agent
cannot widen its own authority, cannot mint another agent, and always traces to
a KYC-verified institution — and to record that enforcement now runs at both
ends.
