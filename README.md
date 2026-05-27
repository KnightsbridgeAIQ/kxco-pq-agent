# kxco-pq-agent

Post-quantum AI agent and robot identity for the KXCO platform.

Institutions that hold a `KxcoIdentity` (from `kxco-pq-sdk`) can sponsor machine identities — LLMs, robots, IoT devices, and automated processes — that cannot pass KYC themselves. The sponsoring institution signs the agent's ML-DSA-65 public key and a structured capability scope, anchoring the agent's authority to their own verified identity.

**Not open source.** This package is part of the KXCO Chain platform. Contact hello@kxco.ai for licensing.

---

## How it works

1. A KYC'd institution generates an ML-DSA-65 keypair for the agent
2. The institution signs a credential binding the agent's public key to a capability scope
3. The agent presents this credential with every relay request, signed with its own private key
4. The KXCO relay validates both the credential (institution's signature) and the intent (agent's signature) before submitting to chain

The credential scope is locked at issuance. To change an agent's permissions, revoke and re-issue.

---

## Install

```bash
npm install kxco-pq-agent
```

---

## Usage

### Issue an agent credential

```js
import { KxcoAgentIdentity } from 'kxco-pq-agent'

// `sponsor` is a KxcoIdentity from kxco-pq-sdk
const agent = await KxcoAgentIdentity.create({
  sponsor,
  label:     'Trading Bot v2',
  agentType: 'llm',
  model:     'claude-opus-4-7',   // optional — model/firmware/version string
  scope: {
    payments: {
      maxPerTransaction: 5000,   // ARMR, in smallest denomination
      maxPerDay:         50000,
      allowedRecipients: [
        '0xAbC123...',                // EVM address
        'aa29f37ab7f4b2cf',           // KXCO kid
      ],
    },
    attestations: {
      purposes: ['trade-confirmation', 'settlement-receipt'],
    },
    auditLog:    true,
    credentials: false,
  },
  expiresIn: '90d',   // '30d', '1y', or seconds as a number
  chain,              // optional KxcoChain — records the credential on-chain
})
```

### Sign a message

```js
const signature = await agent.sign(new TextEncoder().encode('hello'))
```

### Export and restore

```js
// Save to secure storage
const exported = agent.export()

// Restore in another process
const restored = await KxcoAgentIdentity.import(exported)
```

### Send relay operations

```js
import { KxcoChain } from 'kxco-pq-chain'

const chain = new KxcoChain({ relay: 'https://relay.kxco.ai', identity: sponsor })
const client = agent.toChainClient('https://relay.kxco.ai')

const result = await client.anchorAttestation({
  payloadHash: '9f86d081884c7d65...',
  purpose:     'trade-confirmation',
})
// → { txHash: '0x...', blockNumber: 228345 }

await client.anchorAuditRoot({ rootHash: '...', entryCount: 100 })
await client.transfer({ recipientKid: 'aa29f37ab7f4b2cf', amount: 1000 })
```

### Verify a credential

```js
const result = await KxcoAgentIdentity.verify(credential, {
  sponsorPublicKey: sponsor.publicKey,  // optional — skip to check format only
})
// → { valid: true, agentKid: '...', sponsorKid: '...', scope: {...} }
```

### Revoke an agent

```js
await KxcoAgentIdentity.revoke(agent.credential.agentKid, {
  chain,
  reason: 'Decommissioned',
})
```

---

## Scope manifest

The scope is signed by the institution and cannot be modified after issuance.

```ts
interface AgentScope {
  payments?: {
    maxPerTransaction: number   // in smallest denomination
    maxPerDay:         number
    allowedRecipients: string[] // EVM addresses (0x + 40 hex) or KXCO kids (16 hex)
  }
  attestations?: {
    purposes: string[]          // allowed purpose strings
  }
  auditLog?:    boolean         // can anchor audit checkpoints
  credentials?: boolean         // can manage credentials (use sparingly)
}
```

The scope hash (SHA-256 of JCS-canonical scope JSON) is stored on-chain at issuance.

---

## Agent types

| Type | Use |
|------|-----|
| `llm` | Large language models and AI assistants |
| `robot` | Physical robots and automated machinery |
| `iot` | IoT devices and sensors |
| `process` | Automated software processes and daemons |

---

## Authors

Shayne Heffernan and John Heffernan — KXCO by Knightsbridge

hello@kxco.ai | https://kxco.ai
