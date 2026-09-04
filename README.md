# kxco-pq-agent

Post-quantum identity for AI agents and autonomous systems.

---

## Release integrity

Every release of this package is checkable without asking us for anything.

- **Provenance.** Each release carries a SLSA provenance attestation tying the
  published tarball to the commit and workflow that built it. Verify with
  `npm audit signatures`, or read it directly from
  `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-agent@<version>`.
- **Bill of materials.** A CycloneDX SBOM is published as a GitHub Release asset
  at `releases/download/v<version>/sbom.cyclonedx.json`, a permanent
  unauthenticated URL. Not an expiring build artifact.
- **Pinned where it matters.** Third-party dependencies are pinned to exact
  versions, never ranges, so the code that performs the cryptography cannot
  change without a release. Sibling `kxco-*` packages sit on caret ranges
  deliberately: it means a correctness fix in the base package reaches you
  without a release of every package above it. That is not theoretical. When
  `@noble/post-quantum` 0.7.1 was found to fail NIST SLH-DSA verification
  vectors, the revert in the base package propagated here on the next install.
  Every GitHub Action is pinned by 40-character commit SHA.
- **Conformance underneath.** The cryptography comes from
  [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
  is run against **2,103 NIST ACVP vectors: 1,793 passed, 0 failed, 310 skipped** and a **225-check
  cross-implementation interoperability matrix** against liboqs, Bouncy Castle
  and two pure-Python implementations, in both directions and with negative
  controls. Its published tarball also rebuilds bit-for-bit from its own tag,
  verified in CI on every run.

## The problem it solves

AI systems cannot pass KYC. An LLM, robot, IoT device, or daemon has no legal standing to authenticate itself to a regulated network. This package solves that with a delegation model: a KYC-verified institution sponsors the agent by signing its ML-DSA-65 public key alongside a locked capability scope. The agent then signs its own relay operations independently, presenting the sponsor's credential as proof of authority. The KXCO relay validates both signatures before accepting any intent — the institution's approval is cryptographically bound to every action the agent takes.

---

## When to use this

Use this package when deploying LLMs, robots, IoT devices, or daemons that need to perform on-chain operations — payments, attestation anchoring, audit checkpointing — with verifiable, auditable scope controlled by a licensed institution.

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
    maxPerTransaction: 5000,       // maximum ARMR per transfer (positive number)
    maxPerDay:         50000,      // rolling daily cap across all transfers
    allowedRecipients: [           // EVM address (0x + 40 hex) or KXCO kid (16 hex chars)
      '0xAbCdEf...',
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

## API

### KxcoAgentIdentity

**`KxcoAgentIdentity.create(opts)` → `Promise<KxcoAgentIdentity>`**

Generates an ML-DSA-65 keypair for the agent and has the sponsor sign the credential.

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `sponsor` | `{ kid: string, sign(msg: Uint8Array): Promise<Uint8Array> }` | Yes | The sponsoring KxcoIdentity |
| `label` | `string` | Yes | Human-readable name for this agent |
| `agentType` | `'llm' \| 'robot' \| 'iot' \| 'process'` | Yes | Category of the agent |
| `model` | `string` | No | Model, firmware, or version identifier |
| `scope` | `object` | Yes | Capability manifest (see above) |
| `expiresIn` | `string \| number` | Yes | Duration: `'30d'`, `'1y'`, or seconds as a number |
| `chain` | `KxcoChain` | No | If provided, registers the credential on-chain at issuance |

**`agent.toChainClient(relay, opts?)` → `AgentChainClient`**

Returns a relay client that automatically attaches the agent's credential and signature to every request.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `relay` | `string` | — | Relay base URL, e.g. `'https://relay.kxco.ai'` |
| `opts.timeout` | `number` | `10000` | Request timeout in milliseconds |

**`agent.sign(message)` → `Promise<Uint8Array>`**

Signs an arbitrary message with the agent's ML-DSA-65 private key.

**`agent.export()` → `object`**

Serialises the full identity including the secret key. Store securely.

**`KxcoAgentIdentity.import(exported)` → `Promise<KxcoAgentIdentity>`**

Restores an agent identity from a previously exported object.

**`KxcoAgentIdentity.verify(credential, opts?)` → `Promise<{ valid, agentKid, sponsorKid, scope, ... }>`**

Verifies an agent credential envelope.

- Without `opts.sponsorPublicKey`: checks format and expiry only.
- With `opts.sponsorPublicKey` (Uint8Array): performs full ML-DSA-65 signature verification.

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

## Part of the KXCO stack

| Package | Purpose |
|---------|---------|
| `kxco-post-quantum` | ML-DSA-65 and ML-KEM primitives |
| `kxco-pq-sdk` | KxcoIdentity — human and institution identities |
| `kxco-pq-agent` | This package — machine and agent identities |

Contact: hello@kxco.ai | https://kxco.ai

---

## Authors

Shayne Heffernan and John Heffernan — KXCO by Knightsbridge
