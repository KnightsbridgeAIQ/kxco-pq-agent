# kxco-pq-agent

**Post-quantum identity for AI agents: an ML-DSA-87 or ML-DSA-65 key, a locked scope and the signature of the KYC-verified institution that answers for the agent.**

[![npm](https://img.shields.io/npm/v/kxco-pq-agent?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-agent)
[![downloads](https://img.shields.io/npm/dm/kxco-pq-agent?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-pq-agent)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-pq-agent)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-agent)](https://socket.dev/npm/package/kxco-pq-agent)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-agent.svg)](https://nodejs.org)

AI systems cannot pass KYC. An LLM, robot, IoT device, or daemon has no legal standing to authenticate itself to a regulated network. This package solves that with a delegation model: a KYC-verified institution sponsors the agent by signing its ML-DSA-87 or ML-DSA-65 public key alongside a locked capability scope. The agent then signs its own relay operations independently, presenting the sponsor's credential as proof of authority. The KXCO relay validates both signatures before accepting any intent, so the institution's approval is cryptographically bound to every action the agent takes.

- **Every agent answers to a named institution.** A KYC-verified sponsor signs the agent's ML-DSA-87 or ML-DSA-65 key and scope at issuance, and can record the key and a hash of the scope on Armature L1 through `kxco-pq-chain`, so the question of who authorised an action has a legal entity for an answer.
- **Authority fixed at issuance.** The sponsor signs the capability scope into the credential, so the agent cannot widen it: new permissions mean the sponsor revokes and re-issues.
- **Enforced at both ends.** The relay checks the signed scope behind the agent, and `checkScope()` checks it in front: offline, with no round trip, naming the limit that stopped it, and failing closed.
- **Every action signed and bound.** Each relay intent carries the agent's own ML-DSA-87 or ML-DSA-65 signature over the operation and its payload, a fresh nonce, a timestamp and the hash of the sponsor's credential.
- **Any autonomous system, always with an end date.** LLMs, robots, IoT devices and daemons each get a typed identity, and expiry is mandatory, so a short-lived task never leaves a long-lived key behind.
- **Proven underneath.** 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed, in [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md).
- **A supply chain you can check.** SLSA provenance and a CycloneDX SBOM on every release since 1.0.7, third-party dependencies pinned to exact versions, and every GitHub Action pinned by commit SHA.

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [Scope manifest](#scope-manifest) · [The containment model](#the-containment-model) · [For institutions](#for-institutions) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## When to use this

Use this package when deploying LLMs, robots, IoT devices, or daemons that need to perform on-chain operations (payments, attestation anchoring, audit checkpointing) with verifiable, auditable scope controlled by a licensed institution.

---

## Install

```bash
npm install kxco-pq-agent
```

---

## Quick start

```js
import { KxcoAgentIdentity } from 'kxco-pq-agent'

// sponsor is a KxcoIdentity from kxco-pq-sdk
// it must have .kid (string) and .sign(Uint8Array) -> Promise<Uint8Array>

const agent = await KxcoAgentIdentity.create({
  sponsor,
  label:     'Settlement Bot',
  agentType: 'llm',
  scope: {
    attestations: { purposes: ['trade-confirmation'] },
    auditLog: true,
  },
  expiresIn: '90d',
})

// Connect to the relay and anchor an attestation
const client = agent.toChainClient('https://relay.kxco.ai')

const result = await client.anchorAttestation({
  payloadHash: '9f86d081884c7d65...',
  purpose:     'trade-confirmation',
})
// { txHash: '0x...', blockNumber: 228345 }
```

---

## Scope manifest

The scope is signed by the sponsor at issuance and cannot be changed. To update an agent's permissions, revoke and re-issue.

```js
scope: {
  payments: {
    maxPerTransaction: 5000,       // maximum ARMR per transfer (positive integer)
    maxPerDay:         50000,      // rolling daily cap across all transfers
    allowedRecipients: [           // EVM address (0x + 40 hex) or KXCO kid (16 hex chars)
      '0x1234567890abcdef1234567890abcdef12345678',
      'aa29f37ab7f4b2cf',
    ],
  },
  attestations: {
    purposes: ['trade-confirmation', 'settlement-receipt'],  // allowed purpose strings
  },
  auditLog:    true,   // permits anchorAuditRoot calls
  credentials: false,  // permits credential management (use sparingly)
}
```

All fields are optional. Omit a section entirely to deny that capability. The scope hash (SHA-256 of the JCS-canonical scope JSON) is stored on-chain at issuance so the relay can verify integrity.

---

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

---

## API

### KxcoAgentIdentity

**`KxcoAgentIdentity.create(opts)` → `Promise<KxcoAgentIdentity>`**

Generates an ML-DSA-65 keypair for the agent, or an ML-DSA-87 one with `alg: 'ML-DSA-87'`, and has the sponsor sign the credential.

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `sponsor` | `{ kid: string, sign(msg: Uint8Array): Promise<Uint8Array> }` | Yes | The sponsoring KxcoIdentity |
| `label` | `string` | Yes | Human-readable name for this agent, one line of text |
| `agentType` | `'llm' \| 'robot' \| 'iot' \| 'process'` | Yes | Category of the agent |
| `model` | `string` | No | Model, firmware, or version identifier, one line of text |
| `scope` | `object` | Yes | Capability manifest (see above) |
| `expiresIn` | `string \| number` | Yes | Duration: `'30d'`, `'1y'`, or seconds as a number |
| `chain` | `KxcoChain` | No | If provided, registers the credential on-chain at issuance |
| `alg` | `'ML-DSA-65' \| 'ML-DSA-87'` | No | The agent key's parameter set. Defaults to `'ML-DSA-65'` |

The sponsor's parameter set is read from its key: `sponsor.publicKeyHex` (a
kxco-pq-sdk `KxcoIdentity` has one) or `sponsor.getPublicKey()`, or failing both
from `sponsor.alg`. A stated `alg` that disagrees with the key is refused, and so
is a sponsor whose signature is not the set it was read as. An ML-DSA-65 sponsor
signs the credential exactly as before. An ML-DSA-87 sponsor's credential
carries `sponsorAlg: 'ML-DSA-87'` and is signed over
`kxco-agent-credential-v1.1`, which puts the algorithm on the second line,
inside the signed bytes.

**`agent.toChainClient(relay, opts?)` → `AgentChainClient`**

Returns a relay client that automatically attaches the agent's credential and signature to every request. An ML-DSA-65 agent signs `kxco-relay-agent-v1` as before. An ML-DSA-87 agent signs `kxco-relay-agent-v1.1`, the same lines with `alg: ML-DSA-87` after the first, and sends `alg` in the intent.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `relay` | `string` | none | Relay base URL, e.g. `'https://relay.kxco.ai'` |
| `opts.timeout` | `number` | `10000` | Request timeout in milliseconds |

**`agent.sign(message)` → `Promise<Uint8Array>`**

Signs an arbitrary message with the agent's private key, in the set the key belongs to. `agent.alg` reports it.

**`agent.export()` → `object`**

Serialises the full identity including the secret key. Store securely.

**`KxcoAgentIdentity.import(exported)` → `Promise<KxcoAgentIdentity>`**

Restores an agent identity from a previously exported object.

**`KxcoAgentIdentity.verify(credential, opts?)` → `Promise<{ valid, agentKid, sponsorKid, scope, ... }>`**

Verifies an agent credential envelope.

- Without `opts.sponsorPublicKey`: checks format and expiry only.
- With `opts.sponsorPublicKey` (Uint8Array): performs full ML-DSA signature verification under the set the key belongs to. A credential with no `sponsorAlg` is read as ML-DSA-65, as every credential made before the field reads; one whose `sponsorAlg` names the other set from the key is refused.

**`KxcoAgentIdentity.revoke(agentKid, { chain, reason? })` → `Promise`**

Revokes an agent credential on-chain. `chain` must be a KxcoChain instance belonging to the original sponsor.

---

### AgentChainClient

Returned by `agent.toChainClient()`. All methods return `Promise<{ txHash: string, blockNumber: number }>`.

**`client.anchorAttestation({ payloadHash, purpose })`**

Anchors an attestation envelope hash on-chain. Requires `scope.attestations` with the matching purpose listed.

**`client.anchorAuditRoot({ rootHash, entryCount })`**

Anchors an audit log checkpoint on-chain. Requires `scope.auditLog: true`.

**`client.transfer({ to, amount })`**

Submits a payment intent. `to` is an EVM address or KXCO kid. `amount` is in ARMR. The relay enforces `allowedRecipients`, `maxPerTransaction`, and `maxPerDay` from the scope.

### `checkScope(scope, action)`

Decide whether a scope permits an action, before attempting it.

```js
import { checkScope } from 'kxco-pq-agent'

// agent.scope grants payments with maxPerTransaction 5000 and maxPerDay 15000
checkScope(agent.scope, {
  type: 'payment', amount: 4500, spentToday: 12000, recipient: '0xAbC…',
})
// { allowed: false,
//   reason: "amount 4500 would take today's total to 16500, past maxPerDay 15000",
//   checked: ['payments.enabled', 'payments.maxPerTransaction', 'payments.maxPerDay'] }
```

The relay enforces the same signed scope behind the agent, and that enforcement
is the one that binds. This runs in front of it: it refuses offline, refuses
without spending a round trip, and names the limit that stopped it.

| Action | Fields | Checked against |
|---|---|---|
| `payment` | `amount`, `recipient`, `spentToday` | `maxPerTransaction`, `maxPerDay`, `allowedRecipients` |
| `attestation` | `purpose` | `attestations.purposes` |
| `auditLog` | none | `auditLog` |
| `credentials` | none | `credentials` |

Returns `{ allowed, reason?, checked }`. `checked` lists every limit the
decision actually evaluated, so a caller can show the control ran.

It fails closed: a capability the scope does not grant is denied, an action type
it does not recognise is denied, and a configured limit that cannot be judged
from the inputs given is denied rather than skipped. Set `maxPerDay` and omit
`spentToday` and the answer is a refusal naming the missing input, never a pass
that skipped the cap.

---

## Agent types

| Type | Use |
|------|-----|
| `llm` | Large language models and AI assistants |
| `robot` | Physical robots and automated machinery |
| `iot` | IoT devices and sensors |
| `process` | Automated software processes and daemons |

---

## The containment model

Three properties hold for every agent identity, and they are the reason to use
this rather than handing an agent a key.

**An agent can never widen its own authority.** The capability scope is fixed
at issuance and enforced relay-side, so an out-of-scope operation is refused
before it reaches the chain. Compromising the agent does not enlarge what the
agent may do.

**An agent can never mint another agent.** Only a KYC-verified sponsor issues
an identity, so there is no path from one compromised agent to a population of
them.

**Every agent traces to a named, KYC-verified institution.** There is no
anonymous or self-signed mode, which is what makes an agent's action
attributable to a legal entity when a supervisor asks who authorised it.

---

## The KXCO post-quantum family

This gives an agent an identity a verified institution answers for. The rest of the family covers the jobs around it:

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

## Release integrity

Every release since 1.0.7 carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-agent@<version>`. A CycloneDX
SBOM is published, from v1.0.7, as a GitHub Release asset at
`releases/download/v<version>/sbom.cyclonedx.json`, a permanent unauthenticated
URL. Sibling `kxco-*` packages sit on caret ranges so a correctness fix in the
base package reaches you on the next install, with no release of every package
above it.

## Security

Agents sign with **ML-DSA-87** or **ML-DSA-65** (NIST FIPS 204) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every release since 1.0.7: verify with `npm audit signatures`
- **CycloneDX SBOM** published with every release since 1.0.7
- `npm run evidence` records this package's identity, its own test run, its SBOM and the `kxco-post-quantum` version actually installed

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

The sponsor's signature covers the agent's key id and public key, the sponsor's key id, the agent type, label, model, scope, issue time and expiry, so a credential with any field changed fails `KxcoAgentIdentity.verify()` against the sponsor's key.

To report a vulnerability, email **security@kxco.ai**.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)
