import { describe, it, test, before } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { KxcoAgentIdentity, AgentChainClient, KxcoPqAgentError, checkScope, validateScope, hashScope } from '../src/index.js'
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

  it('a relay that is not a string is refused with KxcoPqAgentError BAD_CONFIG', async () => {
    const agent = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'cfg', agentType: 'llm', scope: validScope, expiresIn: '1d' })
    const refused = (err) => err instanceof KxcoPqAgentError && err.code === 'BAD_CONFIG'
    for (const relay of [123, {}, [], true]) {
      assert.throws(() => agent.toChainClient(relay), refused, JSON.stringify(relay))
      assert.throws(() => new AgentChainClient({ relay, agent }), refused, JSON.stringify(relay))
    }
  })
})

// ---------------------------------------------------------------------------
// checkScope — the same signed scope, enforced before the relay sees it
// ---------------------------------------------------------------------------

describe('checkScope', () => {
  const scope = {
    payments: {
      maxPerTransaction: 5000,
      maxPerDay: 50000,
      allowedRecipients: ['0xAbCdEf0123456789AbCdEf0123456789AbCdEf01', 'aa29f37ab7f4b2cf'],
    },
    attestations: { purposes: ['trade-confirmation', 'settlement-receipt'] },
    auditLog: true,
    credentials: false,
  }

  test('permits a payment inside every limit', () => {
    const d = checkScope(scope, {
      type: 'payment', amount: 1000, spentToday: 0,
      recipient: '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01',
    })
    assert.equal(d.allowed, true)
    assert.deepEqual(d.checked, [
      'payments.enabled', 'payments.maxPerTransaction',
      'payments.maxPerDay', 'payments.allowedRecipients',
    ])
  })

  test('refuses over maxPerTransaction, naming the limit', () => {
    const d = checkScope(scope, { type: 'payment', amount: 5001, spentToday: 0 })
    assert.equal(d.allowed, false)
    assert.match(d.reason, /exceeds maxPerTransaction 5000/)
  })

  test('refuses when the day cap would be crossed', () => {
    const d = checkScope(scope, {
      type: 'payment', amount: 1000, spentToday: 49500,
      recipient: 'aa29f37ab7f4b2cf',
    })
    assert.equal(d.allowed, false)
    assert.match(d.reason, /past maxPerDay 50000/)
  })

  test('a configured day cap is never silently skipped', () => {
    // spentToday omitted: the limit exists and cannot be judged, so it denies
    // rather than passing an unevaluated control.
    const d = checkScope(scope, { type: 'payment', amount: 10 })
    assert.equal(d.allowed, false)
    assert.match(d.reason, /spentToday is required/)
  })

  test('refuses a recipient outside the list', () => {
    const d = checkScope(scope, {
      type: 'payment', amount: 10, spentToday: 0, recipient: '0x' + '1'.repeat(40),
    })
    assert.equal(d.allowed, false)
    assert.match(d.reason, /not in allowedRecipients/)
  })

  test('EVM recipients match regardless of case', () => {
    const d = checkScope(scope, {
      type: 'payment', amount: 10, spentToday: 0,
      recipient: '0xabcdef0123456789abcdef0123456789abcdef01',
    })
    assert.equal(d.allowed, true)
  })

  test('attestation purposes are held to the list', () => {
    assert.equal(checkScope(scope, { type: 'attestation', purpose: 'trade-confirmation' }).allowed, true)
    const d = checkScope(scope, { type: 'attestation', purpose: 'anything-else' })
    assert.equal(d.allowed, false)
    assert.match(d.reason, /not in attestations.purposes/)
  })

  test('a capability the scope withholds is refused', () => {
    assert.equal(checkScope(scope, { type: 'auditLog' }).allowed, true)
    assert.equal(checkScope(scope, { type: 'credentials' }).allowed, false)
  })

  test('a capability the scope never mentions is refused', () => {
    const d = checkScope({ auditLog: true }, { type: 'payment', amount: 1 })
    assert.equal(d.allowed, false)
    assert.match(d.reason, /does not grant payments/)
  })

  test('an unrecognised action type is refused', () => {
    const d = checkScope(scope, { type: 'wire-transfer' })
    assert.equal(d.allowed, false)
    assert.match(d.reason, /unknown action type/)
  })

  test('an empty scope grants nothing', () => {
    for (const type of ['payment', 'attestation', 'auditLog', 'credentials']) {
      assert.equal(checkScope({}, { type, amount: 1 }).allowed, false)
    }
  })

  test('a spentToday that is not a finite number is denied, not skipped', () => {
    const capped = { payments: { maxPerTransaction: 500, maxPerDay: 1000 } }
    for (const spentToday of [NaN, Infinity, -Infinity]) {
      const d = checkScope(capped, { type: 'payment', amount: 400, spentToday })
      assert.equal(d.allowed, false, `spentToday ${spentToday}`)
      assert.match(d.reason, /spentToday is required/)
    }
  })

  test('an amount that is not a finite number is denied', () => {
    for (const amount of [NaN, Infinity]) {
      assert.equal(checkScope({ payments: {} }, { type: 'payment', amount }).allowed, false, `amount ${amount}`)
    }
  })

  test('a section or limit of the wrong type is denied, naming it', () => {
    const cases = [
      [{ payments: { maxPerTransaction: 'abc' } }, { type: 'payment', amount: 1e12 }, 'payments.maxPerTransaction'],
      [{ payments: { maxPerTransaction: NaN } }, { type: 'payment', amount: 1e12 }, 'payments.maxPerTransaction'],
      [{ payments: { maxPerDay: '1000' } }, { type: 'payment', amount: 1, spentToday: 0 }, 'payments.maxPerDay'],
      [{ payments: { maxPerDay: NaN } }, { type: 'payment', amount: 1, spentToday: 0 }, 'payments.maxPerDay'],
      [{ payments: { allowedRecipients: 'x' } }, { type: 'payment', amount: 1, recipient: 'x' }, 'payments.allowedRecipients'],
      [{ payments: { allowedRecipients: [42] } }, { type: 'payment', amount: 1, recipient: '42' }, 'payments.allowedRecipients'],
      [{ attestations: { purposes: 'trade-confirmation' } }, { type: 'attestation', purpose: 'trade' }, 'attestations.purposes'],
      [{ attestations: { purposes: [7] } }, { type: 'attestation', purpose: '7' }, 'attestations.purposes'],
      [{ payments: 'abc' }, { type: 'payment', amount: 1 }, 'scope.payments'],
      [{ attestations: ['audit'] }, { type: 'attestation', purpose: 'audit' }, 'scope.attestations'],
      [{ auditLog: 'yes' }, { type: 'auditLog' }, 'scope.auditLog'],
      [{ credentials: 1 }, { type: 'credentials' }, 'scope.credentials'],
    ]
    for (const [s, action, name] of cases) {
      const d = checkScope(s, action)
      assert.equal(d.allowed, false, JSON.stringify(s))
      assert.ok(d.reason.includes(`${name} must be`), d.reason)
    }
  })

  test('a section whose enabled switch is not a boolean is denied, and true, false and absent read as before', () => {
    const actions = {
      payments:     { type: 'payment', amount: 1 },
      attestations: { type: 'attestation', purpose: 'x' },
      auditLog:     { type: 'auditLog' },
      credentials:  { type: 'credentials' },
    }
    for (const [section, action] of Object.entries(actions)) {
      for (const enabled of [0, 1, 'yes', null]) {
        const d = checkScope({ [section]: { enabled } }, action)
        assert.equal(d.allowed, false, `${section}.enabled ${JSON.stringify(enabled)}`)
        assert.ok(d.reason.includes(`scope.${section}.enabled must be a boolean`), d.reason)
      }
      assert.equal(checkScope({ [section]: { enabled: true } }, action).allowed, true)
      assert.equal(checkScope({ [section]: {} }, action).allowed, true)
      assert.equal(checkScope({ [section]: { enabled: false } }, action).allowed, false)
    }
  })
})

// ---------------------------------------------------------------------------
// validateScope, create, verify, import and hashScope: a scope is held to the
// same rules wherever it enters, and refused with KxcoPqAgentError
// ---------------------------------------------------------------------------

const isAgentError = (err) => err instanceof KxcoPqAgentError

// The sponsor-signed message as the relay recomputes it. Used to sign a
// credential the way an earlier version could, with a line break in a field.
function signedAsBefore(c, secretKey) {
  const msg = new TextEncoder().encode([
    'kxco-agent-credential-v1', c.agentKid, c.agentPublicKey, c.sponsorKid, c.agentType,
    c.label, c.model ?? '', canonicalize(c.scope), c.issuedAt, c.expiresAt,
  ].join('\n'))
  return { ...c, sponsorSignature: Buffer.from(mlDsa.sign(secretKey, msg), 'hex').toString('base64url') }
}

describe('scope rules at every entry point', () => {
  test('validateScope refuses a limit that is not a positive integer', () => {
    for (const bad of [NaN, Infinity, -Infinity, 0, -1, 2.5, '5']) {
      for (const name of ['maxPerTransaction', 'maxPerDay']) {
        assert.throws(() => validateScope({ payments: { [name]: bad } }), isAgentError, `${name} ${bad}`)
      }
    }
  })

  test('validateScope refuses a recipient that is not a string', () => {
    for (const r of [{ toString: 1 }, 42, null, ['0x' + '1'.repeat(40)]]) {
      assert.throws(() => validateScope({ payments: { allowedRecipients: [r] } }), isAgentError)
    }
  })

  test('validateScope refuses an enabled switch that is not a boolean', () => {
    for (const enabled of [0, 1, '', 'false', null, {}]) {
      for (const section of ['payments', 'attestations', 'auditLog', 'credentials']) {
        assert.throws(() => validateScope({ [section]: { enabled } }), isAgentError, `${section}.enabled ${JSON.stringify(enabled)}`)
      }
    }
  })

  test('validateScope refuses a scope JCS cannot sign: a fractional number anywhere, or a "__proto__" key', () => {
    assert.throws(() => validateScope({ auditLog: { enabled: true, weight: 2.5 } }), isAgentError)
    assert.throws(() => validateScope(JSON.parse('{"auditLog":true,"__proto__":{"payments":{}}}')), isAgentError)
  })

  test('create refuses a fractional limit', async () => {
    await assert.rejects(
      () => KxcoAgentIdentity.create({
        sponsor: mockSponsor, label: 'x', agentType: 'llm', expiresIn: '1d',
        scope: { payments: { maxPerTransaction: 2.5 } },
      }),
      isAgentError,
    )
  })

  test('create refuses an expiresIn whose expiry is not a representable date', async () => {
    for (const expiresIn of ['999999999y', NaN, Infinity]) {
      await assert.rejects(
        () => KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'x', agentType: 'llm', expiresIn, scope: {} }),
        isAgentError,
        String(expiresIn),
      )
    }
  })

  test('hashScope refuses a fractional number and a "__proto__" key', async () => {
    await assert.rejects(hashScope({ auditLog: true, weight: 2.5 }), isAgentError)
    await assert.rejects(hashScope(JSON.parse('{"auditLog":true,"__proto__":1}')), isAgentError)
  })

  test('verify answers valid: false for a scope JCS cannot sign, rather than throwing', async () => {
    const agent = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'v', agentType: 'llm', scope: validScope, expiresIn: '30d' })
    const credential = { ...agent.credential, scope: { ...agent.credential.scope, weight: 2.5 } }
    for (const opts of [{}, { sponsorPublicKey: sponsorKeypair.publicKey }]) {
      const r = await KxcoAgentIdentity.verify(credential, opts)
      assert.equal(r.valid, false)
      assert.equal(typeof r.error, 'string')
    }
  })

  test('a credential with a "__proto__" member added to its scope does not verify', async () => {
    const agent = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'p', agentType: 'llm', scope: { auditLog: true }, expiresIn: '30d' })
    const text = JSON.stringify(agent.credential)
      .replace('"scope":{', '"scope":{"__proto__":{"payments":{"maxPerTransaction":1000000}},')
    const changed = JSON.parse(text)
    assert.ok(Object.hasOwn(changed.scope, '__proto__'))
    for (const opts of [{}, { sponsorPublicKey: sponsorKeypair.publicKey }]) {
      const r = await KxcoAgentIdentity.verify(changed, opts)
      assert.equal(r.valid, false)
    }
  })

  test('verify and import refuse a scope that validateScope refuses', async () => {
    const agent = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'm', agentType: 'llm', scope: validScope, expiresIn: '30d' })
    const malformed = { ...validScope, attestations: { purposes: 'trade-confirmation' } }
    const r = await KxcoAgentIdentity.verify({ ...agent.credential, scope: malformed })
    assert.equal(r.valid, false)
    assert.match(r.error, /purposes/)
    await assert.rejects(() => KxcoAgentIdentity.import({ ...agent.export(), scope: malformed }), isAgentError)
  })

  test('create refuses a line break or an unpaired surrogate in label, model or the sponsor kid', async () => {
    for (const bad of ['a\nb', 'a\rb', 'x\uD800', '\uDC00y']) {
      for (const opts of [{ label: bad }, { model: bad }, { sponsor: { ...mockSponsor, kid: `${mockSponsor.kid}${bad}` } }]) {
        await assert.rejects(
          () => KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'x', agentType: 'llm', scope: {}, expiresIn: '1d', ...opts }),
          (err) => err instanceof KxcoPqAgentError && /line break or an unpaired surrogate/.test(err.message),
          JSON.stringify(opts),
        )
      }
    }
  })

  test('verify refuses text moved between neighbouring fields, and an unpaired surrogate standing in for U+FFFD', async () => {
    const opts = { sponsorPublicKey: sponsorKeypair.publicKey }
    const agent = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'Settlement', agentType: 'llm', scope: validScope, expiresIn: '30d' })
    // A credential an earlier version could sign: a line break in its label, and no model.
    const { model: _none, ...base } = agent.credential
    const earlier = signedAsBefore({ ...base, label: 'Settlement\nBot' }, sponsorKeypair.secretKey)
    for (const presented of [
      earlier,
      { ...earlier, label: 'Settlement', model: 'Bot\n' },
      { ...earlier, agentType: 'llm\nSettlement', label: 'Bot' },
    ]) {
      const r = await KxcoAgentIdentity.verify(presented, opts)
      assert.equal(r.valid, false, JSON.stringify([presented.agentType, presented.label, presented.model]))
      assert.match(r.error, /line break or an unpaired surrogate/)
    }

    // U+FFFD is a character like any other, and signs; an unpaired surrogate
    // would encode to the same bytes, so it cannot stand in for it.
    const replacement = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'bot\uFFFD', agentType: 'llm', scope: validScope, expiresIn: '30d' })
    assert.equal((await KxcoAgentIdentity.verify(replacement.credential, opts)).valid, true)
    const r = await KxcoAgentIdentity.verify({ ...replacement.credential, label: 'bot\uD800' }, opts)
    assert.equal(r.valid, false)
  })

  test('verify treats an expiresAt that is not a date as expired', async () => {
    const agent = await KxcoAgentIdentity.create({ sponsor: mockSponsor, label: 'e', agentType: 'llm', scope: validScope, expiresIn: '30d' })
    for (const expiresAt of ['never', 'not-a-date', '2026-13-45T00:00:00Z']) {
      const r = await KxcoAgentIdentity.verify({ ...agent.credential, expiresAt })
      assert.equal(r.valid, false, expiresAt)
      assert.match(r.error, /expired/)
    }
  })
})
