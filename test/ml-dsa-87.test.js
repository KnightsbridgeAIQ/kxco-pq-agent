// ML-DSA-87 agents and sponsors: each key decides its own set, an ML-DSA-87
// signature carries its algorithm inside the signed bytes, the other set's key
// is refused, and ML-DSA-65 credentials and intents are exactly as before.

import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'
import { KxcoAgentIdentity, KxcoPqAgentError } from '../src/index.js'
import { canonicalize } from '../src/jcs.js'

const LEGACY = JSON.parse(readFileSync(new URL('./fixtures/legacy-65.json', import.meta.url), 'utf-8'))
const scope = { auditLog: { enabled: true } }
const base = { label: 'bot', agentType: 'process', scope, expiresIn: '30d' }

let s65, s87
const sponsorOf = (kp, mod, extra = {}) => ({
  kid: fingerprint(kp.publicKey),
  sign: async (m) => Buffer.from(mod.sign(kp.secretKey, m), 'hex'),
  ...extra,
})
before(() => {
  s65 = mlDsa.ml_dsa65.keygen()
  s87 = mlDsa87.ml_dsa87.keygen()
})

test("create({ alg: 'ML-DSA-87' }): an ML-DSA-87 agent key that signs and verifies as ML-DSA-87", async () => {
  const agent = await KxcoAgentIdentity.create({ ...base, sponsor: sponsorOf(s65, mlDsa), alg: 'ML-DSA-87' })
  assert.equal(agent.alg, 'ML-DSA-87')
  const pk = await agent.getPublicKey()
  assert.equal(pk.length, 2592)
  assert.equal(agent.kid, fingerprint(pk))
  const sig = await agent.sign(new TextEncoder().encode('hello'))
  assert.equal(sig.length, 4627)
  assert.equal(mlDsa87.verify(pk, 'hello', Buffer.from(sig).toString('hex')), true)
  // An ML-DSA-65 sponsor keeps the v1 credential, whatever the agent's set.
  assert.equal(Object.hasOwn(agent.credential, 'sponsorAlg'), false)
  assert.equal((await KxcoAgentIdentity.verify(agent.credential, { sponsorPublicKey: s65.publicKey })).valid, true)
})

test('create: ML-DSA-65 stays the default and an unknown alg is refused', async () => {
  assert.equal((await KxcoAgentIdentity.create({ ...base, sponsor: sponsorOf(s65, mlDsa) })).alg, 'ML-DSA-65')
  await assert.rejects(KxcoAgentIdentity.create({ ...base, sponsor: sponsorOf(s65, mlDsa), alg: 'ML-DSA-44' }), KxcoPqAgentError)
})

test('an ML-DSA-87 sponsor records sponsorAlg, and only its own key verifies the credential', async () => {
  for (const extra of [
    { publicKeyHex: Buffer.from(s87.publicKey).toString('hex') },
    { getPublicKey: async () => s87.publicKey },
    { alg: 'ML-DSA-87' },
  ]) {
    const agent = await KxcoAgentIdentity.create({ ...base, sponsor: sponsorOf(s87, mlDsa87, extra) })
    assert.equal(agent.credential.sponsorAlg, 'ML-DSA-87', JSON.stringify(Object.keys(extra)))
    assert.equal(Buffer.from(agent.credential.sponsorSignature, 'base64url').length, 4627)
    assert.equal((await KxcoAgentIdentity.verify(agent.credential, { sponsorPublicKey: s87.publicKey })).valid, true)
    assert.deepEqual(await KxcoAgentIdentity.verify(agent.credential, { sponsorPublicKey: s65.publicKey }),
      { valid: false, error: 'sponsor algorithm does not match key' })
  }
})

test('sponsorAlg is inside the signed bytes: stripping or restating it fails', async () => {
  const agent = await KxcoAgentIdentity.create({ ...base, sponsor: sponsorOf(s87, mlDsa87, { alg: 'ML-DSA-87' }) })
  const { sponsorAlg, ...stripped } = agent.credential
  assert.equal(sponsorAlg, 'ML-DSA-87')
  assert.deepEqual(await KxcoAgentIdentity.verify(stripped, { sponsorPublicKey: s87.publicKey }),
    { valid: false, error: 'sponsor algorithm does not match key' })
  assert.deepEqual(await KxcoAgentIdentity.verify(stripped, { sponsorPublicKey: s65.publicKey }),
    { valid: false, error: 'sponsor signature invalid' })
})

test('create: a sponsor that disagrees with itself, or signs in another set, is refused', async () => {
  // Stated alg against the sponsor's own key.
  await assert.rejects(KxcoAgentIdentity.create({
    ...base, sponsor: sponsorOf(s87, mlDsa87, { alg: 'ML-DSA-65', getPublicKey: async () => s87.publicKey }),
  }), /sponsor.alg is ML-DSA-65 but the sponsor's public key is ML-DSA-87/)
  // An ML-DSA-87 sponsor exposing nothing reads as ML-DSA-65; its signature gives it away.
  await assert.rejects(KxcoAgentIdentity.create({ ...base, sponsor: sponsorOf(s87, mlDsa87) }),
    /the sponsor's signature is not ML-DSA-65/)
  await assert.rejects(KxcoAgentIdentity.create({ ...base, sponsor: sponsorOf(s65, mlDsa, { alg: 'ML-DSA-99' }) }),
    KxcoPqAgentError)
})

test('export and import keep an ML-DSA-87 agent signing as ML-DSA-87', async () => {
  const agent = await KxcoAgentIdentity.create({ ...base, sponsor: sponsorOf(s65, mlDsa), alg: 'ML-DSA-87' })
  const again = await KxcoAgentIdentity.import(JSON.parse(JSON.stringify(agent.export())))
  assert.equal(again.alg, 'ML-DSA-87')
  const sig = await again.sign(new TextEncoder().encode('x'))
  assert.equal(mlDsa87.verify(await again.getPublicKey(), 'x', Buffer.from(sig).toString('hex')), true)
})

// The relay message, rebuilt here the way a relay does: v1 for ML-DSA-65, and
// v1.1 with the algorithm on the second line for ML-DSA-87.
function relayMessage(intent, alg) {
  const { operation, agentKid, sponsorKid, nonce, timestamp, credentialHash, payload } = intent
  return new TextEncoder().encode([
    ...(alg ? ['kxco-relay-agent-v1.1', `alg: ${alg}`] : ['kxco-relay-agent-v1']),
    `operation: ${operation}`, `agentKid: ${agentKid}`, `sponsorKid: ${sponsorKid}`,
    `nonce: ${nonce}`, `timestamp: ${timestamp}`, `credentialHash: ${credentialHash}`,
    `payload: ${canonicalize(payload)}`,
  ].join('\n'))
}

async function captureIntent(agent) {
  const realFetch = globalThis.fetch
  let captured
  globalThis.fetch = async (url, init) => {
    captured = JSON.parse(init.body)
    return new Response(JSON.stringify({ ok: true, txHash: '0x1', blockNumber: 1 }), { status: 200 })
  }
  try {
    await agent.toChainClient('http://relay.test').anchorAuditRoot({ rootHash: 'b'.repeat(64), entryCount: 3 })
  } finally {
    globalThis.fetch = realFetch
  }
  return captured
}

test('intents: an ML-DSA-87 agent signs kxco-relay-agent-v1.1 with alg in the intent', async () => {
  const agent = await KxcoAgentIdentity.create({ ...base, sponsor: sponsorOf(s65, mlDsa), alg: 'ML-DSA-87' })
  const intent = await captureIntent(agent)
  assert.equal(intent.alg, 'ML-DSA-87')
  const pk = await agent.getPublicKey()
  assert.equal(mlDsa87.verify(pk, relayMessage(intent, 'ML-DSA-87'), intent.signature), true)
  assert.equal(mlDsa87.verify(pk, relayMessage(intent, null), intent.signature), false, 'not the v1 bytes')
})

test('intents: an ML-DSA-65 agent still signs kxco-relay-agent-v1 with no alg field', async () => {
  const agent = await KxcoAgentIdentity.create({ ...base, sponsor: sponsorOf(s65, mlDsa) })
  const intent = await captureIntent(agent)
  assert.equal(Object.hasOwn(intent, 'alg'), false)
  assert.equal(mlDsa.verify(await agent.getPublicKey(), relayMessage(intent, null), intent.signature), true)
})

test('an agent exported by 1.0.8, before ML-DSA-87, still imports, signs and verifies', async () => {
  const sponsorPublicKey = Buffer.from(LEGACY.sponsorPublicKey, 'hex')
  assert.equal(Object.hasOwn(LEGACY.exported.credential, 'sponsorAlg'), false)
  const r = await KxcoAgentIdentity.verify(LEGACY.exported.credential, { sponsorPublicKey })
  assert.equal(r.valid, true)
  assert.equal(r.label, 'legacy-bot')
  assert.deepEqual(await KxcoAgentIdentity.verify(LEGACY.exported.credential, { sponsorPublicKey: s87.publicKey }),
    { valid: false, error: 'sponsor algorithm does not match key' })

  const agent = await KxcoAgentIdentity.import(LEGACY.exported)
  assert.equal(agent.alg, 'ML-DSA-65')
  const intent = await captureIntent(agent)
  assert.equal(Object.hasOwn(intent, 'alg'), false)
  assert.equal(mlDsa.verify(await agent.getPublicKey(), relayMessage(intent, null), intent.signature), true)
})

// The credential bytes rebuilt from the published layout: v1.1 replaces the
// first line and puts the sponsor's algorithm on the second; the rest is v1.
test('wire format: an ML-DSA-87 sponsor signs kxco-agent-credential-v1.1 with the algorithm on line 2', async () => {
  const agent = await KxcoAgentIdentity.create({ ...base, model: 'm', sponsor: sponsorOf(s87, mlDsa87, { alg: 'ML-DSA-87' }) })
  const c = agent.credential
  const rest = [c.agentKid, c.agentPublicKey, c.sponsorKid, c.agentType, c.label, c.model ?? '',
    canonicalize(c.scope), c.issuedAt, c.expiresAt]
  const bytes = (...xs) => new TextEncoder().encode(xs.join('\n'))
  const sig = Buffer.from(c.sponsorSignature, 'base64url').toString('hex')
  assert.equal(mlDsa87.verify(s87.publicKey, bytes('kxco-agent-credential-v1.1', 'ML-DSA-87', ...rest), sig), true)
  assert.equal(mlDsa87.verify(s87.publicKey, bytes('kxco-agent-credential-v1', ...rest), sig), false)
})
