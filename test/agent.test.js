import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { KxcoAgentIdentity, KxcoPqAgentError } from '../src/index.js'
import { canonicalize } from '../src/jcs.js'

// ── Mock sponsor ─────────────────────────────────────────────────────────────

let sponsorKeypair, sponsorKid, mockSponsor

before(() => {
  sponsorKeypair = mlDsa.ml_dsa65.keygen()
  sponsorKid     = fingerprint(sponsorKeypair.publicKey)
  mockSponsor    = {
    kid:          sponsorKid,
    sign:         async (msg) => Buffer.from(mlDsa.sign(sponsorKeypair.secretKey, msg), 'hex'),
    getPublicKey: async ()    => sponsorKeypair.publicKey,
  }
})

const validScope = {
  payments: {
    enabled:           true,
    maxPerTransaction: 500,
    maxPerDay:         5000,
    allowedRecipients: ['0xAbCdEf1234567890AbCdEf1234567890AbCdEf12', 'aa29f37ab7f4b2cf'],
  },
  attestations: { enabled: true, purposes: ['trade-confirmation'] },
  auditLog:    { enabled: true },
  credentials: { enabled: false },
}

// ── create ───────────────────────────────────────────────────────────────────

describe('KxcoAgentIdentity.create', () => {
  it('creates a valid agent identity', async () => {
    const agent = await KxcoAgentIdentity.create({
      sponsor:   mockSponsor,
      label:     'test-bot',
      agentType: 'llm',
      model:     'claude-opus-4',
      scope:     validScope,
      expiresIn: '30d',
    })
    assert.ok(typeof agent.kid === 'string' && agent.kid.length === 16)
    assert.equal(agent.sponsorKid, sponsorKid)
    assert.equal(agent.agentType, 'llm')
    assert.equal(agent.label, 'test-bot')
    assert.equal(agent.model, 'claude-opus-4')
    assert.equal(agent.credential['kxco-agent'], '1')
    assert.equal(agent.credential.sponsorKid, sponsorKid)
    assert.ok(typeof agent.credential.sponsorSignature === 'string')
  })

  it('throws if expiresIn is missing', async () => {
    await assert.rejects(
      () => KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'x', agentType: 'llm', scope: validScope }),
      /expiresIn is required/
    )
  })

  it('throws for invalid agentType', async () => {
    await assert.rejects(
      () => KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'x', agentType: 'cyborg', scope: validScope, expiresIn: '1d' }),
      /agentType must be one of/
    )
  })

  it('throws when maxPerTransaction exceeds maxPerDay', async () => {
    await assert.rejects(
      () => KxcoAgentIdentity.create({
        sponsor: mockSponsor, label: 'x', agentType: 'llm', expiresIn: '1d',
        scope: { payments: { enabled: true, maxPerTransaction: 1000, maxPerDay: 500 } },
      }),
      /must not exceed maxPerDay/
    )
  })

  it('throws for invalid allowedRecipients entry', async () => {
    await assert.rejects(
      () => KxcoAgentIdentity.create({
        sponsor: mockSponsor, label: 'x', agentType: 'llm', expiresIn: '1d',
        scope: { payments: { enabled: true, allowedRecipients: ['not-a-valid-address'] } },
      }),
      /invalid recipient/
    )
  })

  it('accepts both EVM addresses and KXCO kids in allowedRecipients', async () => {
    const agent = await KxcoAgentIdentity.create({
      sponsor: mockSponsor, label: 'x', agentType: 'iot', expiresIn: '7d',
      scope: {
        payments: {
          enabled: true,
          allowedRecipients: ['0xAbCdEf1234567890AbCdEf1234567890AbCdEf12', 'aa29f37ab7f4b2cf'],
        },
      },
    })
    assert.ok(agent.kid)
  })
})

// ── sign ─────────────────────────────────────────────────────────────────────

describe('KxcoAgentIdentity sign', () => {
  it('agent signs with its own key and verifies with agent public key', async () => {
    const agent   = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'x', agentType: 'iot', scope: validScope, expiresIn: '7d' })
    const message = new TextEncoder().encode('test payload')
    const sig     = await agent.sign(message)
    const pubKey  = await agent.getPublicKey()
    assert.ok(mlDsa.verify(pubKey, message, Buffer.from(sig).toString('hex')))
  })

  it('agent signature does not verify with sponsor key', async () => {
    const agent   = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'x', agentType: 'llm', scope: validScope, expiresIn: '7d' })
    const message = new TextEncoder().encode('test payload')
    const sig     = await agent.sign(message)
    const ok      = mlDsa.verify(sponsorKeypair.publicKey, message, Buffer.from(sig).toString('hex'))
    assert.equal(ok, false)
  })
})

// ── export / import ──────────────────────────────────────────────────────────

describe('KxcoAgentIdentity export/import', () => {
  it('round-trips identity correctly', async () => {
    const agent    = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'round-trip', agentType: 'robot', scope: validScope, expiresIn: '14d' })
    const exported = agent.export()
    const loaded   = await KxcoAgentIdentity.import(exported)

    assert.equal(loaded.kid,        agent.kid)
    assert.equal(loaded.sponsorKid, agent.sponsorKid)
    assert.equal(loaded.label,      agent.label)
    assert.equal(loaded.agentType,  agent.agentType)
    assert.deepEqual(loaded.scope, agent.scope)

    const msg = new TextEncoder().encode('round-trip test')
    const sig = await loaded.sign(msg)
    const pub = await loaded.getPublicKey()
    assert.ok(mlDsa.verify(pub, msg, Buffer.from(sig).toString('hex')))
  })

  it('throws for unsupported import format', async () => {
    await assert.rejects(
      () => KxcoAgentIdentity.import({ 'kxco-agent-identity': '99' }),
      /invalid or unsupported/
    )
  })
})

// ── verify ───────────────────────────────────────────────────────────────────

describe('KxcoAgentIdentity.verify', () => {
  it('verifies a valid credential with sponsor public key', async () => {
    const agent  = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'v', agentType: 'process', scope: validScope, expiresIn: '30d' })
    const result = await KxcoAgentIdentity.verify(agent.credential, { sponsorPublicKey: sponsorKeypair.publicKey })
    assert.equal(result.valid,      true)
    assert.equal(result.agentKid,   agent.kid)
    assert.equal(result.sponsorKid, sponsorKid)
    assert.equal(result.agentType,  'process')
  })

  it('rejects a tampered sponsorSignature', async () => {
    const agent    = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'v', agentType: 'llm', scope: validScope, expiresIn: '30d' })
    const tampered = { ...agent.credential, sponsorSignature: 'AAAA' }
    const result   = await KxcoAgentIdentity.verify(tampered, { sponsorPublicKey: sponsorKeypair.publicKey })
    assert.equal(result.valid, false)
    assert.match(result.error, /signature invalid/)
  })

  it('rejects an expired credential', async () => {
    const agent   = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'v', agentType: 'llm', scope: validScope, expiresIn: '1d' })
    const expired = { ...agent.credential, expiresAt: new Date(Date.now() - 1000).toISOString() }
    const result  = await KxcoAgentIdentity.verify(expired)
    assert.equal(result.valid, false)
    assert.match(result.error, /expired/)
  })

  it('checks format without sponsorPublicKey', async () => {
    const agent  = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'v', agentType: 'robot', scope: validScope, expiresIn: '30d' })
    const result = await KxcoAgentIdentity.verify(agent.credential)
    assert.equal(result.valid, true)
  })
})

// ── toChainClient / AgentChainClient ─────────────────────────────────────────

async function withMockRelay(handler, fn) {
  const server = createServer(handler)
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  const { port } = server.address()
  try {
    await fn(`http://127.0.0.1:${port}`)
  } finally {
    await new Promise(r => server.close(r))
  }
}

describe('AgentChainClient (toChainClient)', () => {
  it('sends agent-extended intent and receives txHash', async () => {
    let captured = null
    await withMockRelay(
      (req, res) => {
        let body = ''
        req.on('data', c => { body += c })
        req.on('end', () => {
          captured = JSON.parse(body)
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ ok: true, txHash: '0xdeadbeef', blockNumber: 999 }))
        })
      },
      async (relayUrl) => {
        const agent  = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'chain-test', agentType: 'llm', scope: validScope, expiresIn: '30d' })
        const chain  = agent.toChainClient(relayUrl)
        const result = await chain.anchorAttestation({ payloadHash: 'a'.repeat(64), purpose: 'trade-confirmation' })

        assert.equal(result.txHash,       '0xdeadbeef')
        assert.equal(result.blockNumber,  999)
        assert.equal(captured.operation,  'anchorAttestation')
        assert.equal(captured.agentKid,   agent.kid)
        assert.equal(captured.sponsorKid, sponsorKid)
        assert.ok(typeof captured.agentCredential === 'string')
        assert.ok(typeof captured.credentialHash  === 'string')
        assert.ok(typeof captured.signature       === 'string')
        assert.ok(typeof captured.nonce           === 'string')
        assert.ok(typeof captured.timestamp       === 'number')
      }
    )
  })

  it('intent is signed by the agent key (not the sponsor)', async () => {
    let captured = null
    await withMockRelay(
      (req, res) => {
        let body = ''
        req.on('data', c => { body += c })
        req.on('end', () => {
          captured = JSON.parse(body)
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ ok: true, txHash: '0xabc', blockNumber: 1 }))
        })
      },
      async (relayUrl) => {
        const agent = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'sig-verify', agentType: 'robot', scope: validScope, expiresIn: '30d' })
        const chain = agent.toChainClient(relayUrl)
        await chain.transfer({ to: '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12', amount: 100 })

        const { operation, agentKid, sponsorKid: skid, nonce, timestamp, credentialHash, payload, signature } = captured
        const enc = new TextEncoder()
        const msg = enc.encode([
          'kxco-relay-agent-v1',
          `operation: ${operation}`,
          `agentKid: ${agentKid}`,
          `sponsorKid: ${skid}`,
          `nonce: ${nonce}`,
          `timestamp: ${timestamp}`,
          `credentialHash: ${credentialHash}`,
          `payload: ${canonicalize(payload)}`,
        ].join('\n'))

        const agentPubKey = await agent.getPublicKey()
        assert.ok(mlDsa.verify(agentPubKey, msg, signature), 'intent must be signed by agent key')
        assert.equal(mlDsa.verify(sponsorKeypair.publicKey, msg, signature), false, 'sponsor key must not verify agent intent')
      }
    )
  })

  it('throws KxcoPqAgentError on relay error response', async () => {
    await withMockRelay(
      (req, res) => {
        let body = ''
        req.on('data', c => { body += c })
        req.on('end', () => {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: 'scope exceeded', code: 'SCOPE_EXCEEDED' }))
        })
      },
      async (relayUrl) => {
        const agent = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'err-test', agentType: 'iot', scope: validScope, expiresIn: '30d' })
        const chain = agent.toChainClient(relayUrl)
        await assert.rejects(
          () => chain.anchorAttestation({ payloadHash: 'b'.repeat(64), purpose: 'x' }),
          (err) => err instanceof KxcoPqAgentError && err.message === 'scope exceeded'
        )
      }
    )
  })
})
