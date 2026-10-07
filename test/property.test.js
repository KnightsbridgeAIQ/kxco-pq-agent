// Property-based tests with fast-check.
//
// test/agent.test.js pins the cases someone thought to write down. These ask
// the general question instead: for ANY label, agent type, model and scope,
// does a sponsored credential verify under the sponsor's key and under no
// other; does changing any one signed field make it fail; does export then
// import give back the same agent; and does checkScope refuse every action the
// scope does not grant? fast-check generates the inputs and, when a property
// breaks, shrinks the failing case to the smallest one that still breaks it,
// so a failure arrives as a minimal reproduction rather than a random blob.
//
// Nothing here touches the network. The sponsor is a local object with a kid
// and a sign() built from kxco-post-quantum, and no test builds a chain client.
//
// Runs on whichever kxco-post-quantum backend is live.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fc from 'fast-check'
import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'
import { KxcoAgentIdentity, KxcoPqAgentError, validateScope, checkScope, hashScope } from '../src/index.js'
import { canonicalize } from '../src/jcs.js'

// Every credential case generates an agent key and has the sponsor sign, so a
// modest run count keeps the file fast on the JavaScript backend. The scope
// checks are pure and quick, so they get far more cases.
const SIGNING = { numRuns: 25 }
const PURE = { numRuns: 2000 }

// A KxcoIdentity-like sponsor: a kid and a sign(message) that resolves to the
// signature bytes. Deterministic keys, so a failure reproduces from its seed.
function localSponsor(info) {
  const key = mlDsa.keypairFromMaster(new Uint8Array(32).fill(7), info)
  return {
    publicKey: key.publicKey,
    sponsor: {
      kid: fingerprint(key.publicKey),
      sign: async (msg) => Buffer.from(mlDsa.sign(key.secretKey, msg), 'hex'),
    },
  }
}
const A = localSponsor('kxco-pq-agent-property-sponsor-a')
const B = localSponsor('kxco-pq-agent-property-sponsor-b')

// ── generators ──────────────────────────────────────────────────────────────

const ACTION_TYPES = ['payment', 'attestation', 'auditLog', 'credentials']
const agentType = fc.constantFrom('llm', 'robot', 'iot', 'process')
// Any non-empty text, control characters, line breaks and unpaired surrogates
// included: the signing message is line-joined, so create() refuses a line
// break or an unpaired surrogate in a field, and both are worth trying.
const text = fc.oneof(
  fc.string({ unit: 'grapheme', minLength: 1, maxLength: 30 }),
  fc.string({ unit: 'binary-ascii', minLength: 1, maxLength: 30 }),
  fc.string({ unit: fc.constantFrom('a', '\n', '\r', '\uFFFD', '\uD800', '\uDBFF', '\uDC00', '\uD83D\uDE00'), minLength: 1, maxLength: 6 }),
)
const model = fc.option(text, { nil: undefined })
const expiresIn = fc.oneof(
  fc.integer({ min: 3600, max: 5 * 365 * 86400 }),
  fc.tuple(fc.integer({ min: 1, max: 3650 }), fc.constantFrom('d', 'h')).map(([n, u]) => `${n}${u}`),
  fc.integer({ min: 1, max: 10 }).map((n) => `${n}y`),
)

// Recipients and purposes come partly from small fixed pools, so that an
// action's recipient or purpose often is, and often is not, in the scope.
const POOL = [
  '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01',
  '0x1111111111111111111111111111111111111111',
  'aa29f37ab7f4b2cf',
  '0123456789abcdef',
]
const PURPOSES = ['trade-confirmation', 'settlement-receipt', 'audit']
const recipient = fc.oneof(
  { weight: 3, arbitrary: fc.constantFrom(...POOL) },
  { weight: 1, arbitrary: fc.stringMatching(/^0x[0-9a-fA-F]{40}$/) },
  { weight: 1, arbitrary: fc.stringMatching(/^[0-9a-f]{16}$/) },
)
const purpose = fc.oneof(
  { weight: 3, arbitrary: fc.constantFrom(...PURPOSES) },
  { weight: 1, arbitrary: fc.string({ minLength: 1, maxLength: 20 }).filter((s) => s.trim() !== '') },
)
// Mostly on, so the limits behind the switch get exercised.
const enabled = fc.oneof({ weight: 3, arbitrary: fc.constant(true) }, { weight: 1, arbitrary: fc.constant(false) })

// Limits are positive integers, the domain the JCS subset signs. The pair is
// ordered so maxPerTransaction never exceeds maxPerDay when both are present.
const limit = fc.integer({ min: 1, max: 1_000_000 })
const payments = fc.record({
  enabled,
  maxPerTransaction: limit,
  maxPerDay: limit,
  allowedRecipients: fc.array(recipient, { maxLength: 4 }),
}, { requiredKeys: [] }).map((p) => {
  if (p.maxPerTransaction === undefined || p.maxPerDay === undefined) return p
  return { ...p, maxPerTransaction: Math.min(p.maxPerTransaction, p.maxPerDay), maxPerDay: Math.max(p.maxPerTransaction, p.maxPerDay) }
})
const attestations = fc.record({ enabled, purposes: fc.array(purpose, { maxLength: 4 }) }, { requiredKeys: [] })
const toggle = fc.oneof(fc.boolean(), fc.record({ enabled }, { requiredKeys: [] }))
// A section is usually present, and sometimes null or left out altogether.
const section = (arb) => fc.oneof(
  { weight: 6, arbitrary: arb },
  { weight: 1, arbitrary: fc.constant(null) },
  { weight: 1, arbitrary: fc.constant(undefined) },
)
const leaveOutUndefined = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined))

// A scope as the README describes it. Every value here passes validateScope.
const scope = fc.record({
  payments: section(payments),
  attestations: section(attestations),
  auditLog: section(toggle),
  credentials: section(toggle),
}).map(leaveOutUndefined)

// A scope-shaped value where any slot may hold the wrong thing: wrong types,
// empty and blank strings, zero, negative and fractional limits, NaN and the
// infinities, switches that are not booleans, malformed recipients. Each slot
// is usually plausible, so a fair share of cases are well formed.
const junk = fc.oneof(
  fc.integer({ min: -5, max: 5 }),
  fc.double(),
  fc.string({ maxLength: 8 }),
  fc.boolean(),
  fc.constant(null),
  fc.constant({ toString: 1 }),
  fc.array(fc.oneof(fc.string({ maxLength: 8 }), fc.integer()), { maxLength: 3 }),
)
const mostly = (good, bad = junk) => fc.oneof({ weight: 4, arbitrary: good }, { weight: 1, arbitrary: bad })
const messyLimit = mostly(fc.integer({ min: -100, max: 1_000_000 }))
const messyEnabled = mostly(enabled)
const messyToggle = fc.oneof(fc.boolean(), fc.record({ enabled: messyEnabled }, { requiredKeys: [] }))
const messyScope = mostly(fc.record({
  payments: mostly(fc.record({
    enabled: messyEnabled,
    maxPerTransaction: messyLimit,
    maxPerDay: messyLimit,
    allowedRecipients: mostly(fc.array(mostly(recipient, fc.oneof(fc.string({ maxLength: 20 }), junk, recipient.map((r) => [r]))), { maxLength: 4 })),
  }, { requiredKeys: [] })),
  attestations: mostly(fc.record({
    enabled: messyEnabled,
    purposes: mostly(fc.array(mostly(purpose, fc.oneof(fc.constantFrom('', '  '), junk)), { maxLength: 4 })),
  }, { requiredKeys: [] })),
  auditLog: mostly(messyToggle),
  credentials: mostly(messyToggle),
}, { requiredKeys: [] }))

// An action carrying every field the four types read, each sometimes missing
// (undefined) or the wrong type.
const amount = fc.oneof(
  { weight: 4, arbitrary: fc.integer({ min: 1, max: 1000 }) },
  { weight: 2, arbitrary: fc.integer({ min: -10, max: 2_000_000 }) },
  { weight: 1, arbitrary: fc.double() },
  { weight: 1, arbitrary: fc.constantFrom(NaN, Infinity) },
  { weight: 1, arbitrary: fc.constantFrom(undefined, null, 0, '100', true) },
)
const spentToday = fc.oneof(
  { weight: 4, arbitrary: fc.integer({ min: 0, max: 1000 }) },
  { weight: 2, arbitrary: fc.integer({ min: -10, max: 2_000_000 }) },
  { weight: 1, arbitrary: fc.double() },
  { weight: 1, arbitrary: fc.constantFrom(NaN, Infinity, -Infinity) },
  { weight: 1, arbitrary: fc.constantFrom(undefined, null, '0') },
)
const actionRecipient = fc.oneof(
  { weight: 4, arbitrary: fc.constantFrom(...POOL).chain((r) => fc.constantFrom(r, r.toLowerCase(), r.toUpperCase())) },
  { weight: 2, arbitrary: recipient },
  { weight: 1, arbitrary: fc.constantFrom(undefined, 42) },
)
const actionPurpose = fc.oneof({ weight: 4, arbitrary: purpose }, { weight: 1, arbitrary: fc.constantFrom(undefined, 7) })
const action = fc.record({
  type: fc.constantFrom(...ACTION_TYPES),
  amount,
  spentToday,
  recipient: actionRecipient,
  purpose: actionPurpose,
})

// A JSON-shaped value with any keys, integer-like names and "__proto__" among
// them, and now and then a fraction, NaN or an infinity, which JCS refuses.
// Objects are built with Object.fromEntries, so "__proto__" is an own key.
const anyKey = fc.oneof(
  { weight: 6, arbitrary: fc.string({ unit: 'binary', maxLength: 8 }) },
  { weight: 3, arbitrary: fc.nat(1000).map(String) },
  { weight: 1, arbitrary: fc.constant('__proto__') },
)
const anyJson = fc.letrec((tie) => ({
  value: fc.oneof(
    { depthSize: 'small' },
    { weight: 3, arbitrary: fc.constant(null) },
    { weight: 3, arbitrary: fc.boolean() },
    { weight: 3, arbitrary: fc.integer() },
    { weight: 1, arbitrary: fc.double() },
    { weight: 3, arbitrary: fc.string({ maxLength: 12 }) },
    { weight: 3, arbitrary: fc.array(tie('value'), { maxLength: 4 }) },
    { weight: 3, arbitrary: fc.uniqueArray(fc.tuple(anyKey, tie('value')), { maxLength: 4, selector: ([k]) => k }).map(Object.fromEntries) },
  ),
})).value

// ── the rules the README states, written out independently ──────────────────

function granted(s) {
  return s === true || (s !== null && typeof s === 'object' && s.enabled !== false)
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
const isLimit = (v) => v === undefined || (Number.isInteger(v) && v > 0)
const switchOk = (section) => !isPlainObject(section) || section.enabled === undefined || typeof section.enabled === 'boolean'

// Whether a scope obeys the manifest rules: sections are objects (auditLog and
// credentials may also be booleans) whose `enabled`, if present, is a boolean;
// limits are positive integers with the transaction cap inside the day cap;
// recipients are EVM addresses or kids, as strings; and purposes are non-empty
// strings. A section switched off is not checked further.
function wellFormed(sc) {
  if (!isPlainObject(sc)) return false
  const { payments: p, attestations: t, auditLog, credentials } = sc
  if (p != null) {
    if (!isPlainObject(p) || !switchOk(p)) return false
    if (p.enabled !== false) {
      if (!isLimit(p.maxPerTransaction) || !isLimit(p.maxPerDay)) return false
      if (p.maxPerTransaction !== undefined && p.maxPerDay !== undefined && p.maxPerTransaction > p.maxPerDay) return false
      if (p.allowedRecipients !== undefined) {
        if (!Array.isArray(p.allowedRecipients)) return false
        if (!p.allowedRecipients.every((r) => typeof r === 'string' && (/^0x[0-9a-fA-F]{40}$/.test(r) || /^[0-9a-f]{16}$/.test(r)))) return false
      }
    }
  }
  if (t != null) {
    if (!isPlainObject(t) || !switchOk(t)) return false
    if (t.enabled !== false && t.purposes !== undefined) {
      if (!Array.isArray(t.purposes)) return false
      if (!t.purposes.every((x) => typeof x === 'string' && x.trim() !== '')) return false
    }
  }
  for (const toggleValue of [auditLog, credentials]) {
    if (toggleValue != null && typeof toggleValue !== 'boolean' && !isPlainObject(toggleValue)) return false
    if (!switchOk(toggleValue)) return false
  }
  return true
}

// Whether JCS can sign a value: every number an integer, and no object key
// named "__proto__".
function signable(v) {
  if (typeof v === 'number') return Number.isInteger(v)
  if (Array.isArray(v)) return v.every(signable)
  if (v !== null && typeof v === 'object') return !Object.hasOwn(v, '__proto__') && Object.values(v).every(signable)
  return true
}

// Whether the section an action reads, and each limit in it, has the type the
// README gives it. Nothing else can be judged.
const SECTION_OF = { payment: 'payments', attestation: 'attestations', auditLog: 'auditLog', credentials: 'credentials' }
function sectionSound(sc, type) {
  const name = SECTION_OF[type]
  const s = name && sc[name]
  if (!name || s == null || s === false) return true
  if (s === true) return name === 'auditLog' || name === 'credentials'
  if (!isPlainObject(s) || !switchOk(s)) return false
  const limit = (v) => v === undefined || (Number.isFinite(v) && v > 0)
  const strings = (v) => v === undefined || (Array.isArray(v) && v.every((x) => typeof x === 'string'))
  if (name === 'payments') return limit(s.maxPerTransaction) && limit(s.maxPerDay) && strings(s.allowedRecipients)
  if (name === 'attestations') return strings(s.purposes)
  return true
}

// Whether the README's rules permit an action, and which limits they name.
function permitted(scope, a) {
  switch (a.type) {
    case 'payment': {
      const p = scope.payments
      if (!granted(p)) return false
      if (!Number.isFinite(a.amount) || !(a.amount > 0)) return false
      if (p.maxPerTransaction !== undefined && a.amount > p.maxPerTransaction) return false
      if (p.maxPerDay !== undefined) {
        if (!Number.isFinite(a.spentToday) || a.spentToday < 0) return false
        if (a.spentToday + a.amount > p.maxPerDay) return false
      }
      if (p.allowedRecipients !== undefined) {
        if (typeof a.recipient !== 'string') return false
        if (!p.allowedRecipients.some((r) => r.toLowerCase() === a.recipient.toLowerCase())) return false
      }
      return true
    }
    case 'attestation': {
      const s = scope.attestations
      if (!granted(s)) return false
      if (s.purposes !== undefined && (typeof a.purpose !== 'string' || !s.purposes.includes(a.purpose))) return false
      return true
    }
    case 'auditLog': return granted(scope.auditLog)
    case 'credentials': return granted(scope.credentials)
    default: return false
  }
}

// The limits a decision on this action must have evaluated before allowing it.
function configuredLimits(scope, a) {
  if (a.type === 'payment') {
    const p = scope.payments
    return ['payments.enabled', ...['maxPerTransaction', 'maxPerDay', 'allowedRecipients']
      .filter((k) => p[k] !== undefined).map((k) => `payments.${k}`)]
  }
  if (a.type === 'attestation') {
    return ['attestations.enabled', ...(scope.attestations.purposes !== undefined ? ['attestations.purposes'] : [])]
  }
  return [a.type]
}

const SIGNED_STRING_FIELDS = ['kxco-agent', 'agentKid', 'agentPublicKey', 'sponsorKid', 'agentType', 'label', 'issuedAt', 'expiresAt']

// Whether a string holds a UTF-16 surrogate that is not half of a pair.
function hasLoneSurrogate(str) {
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = str.charCodeAt(i + 1)
      if (d >= 0xdc00 && d <= 0xdfff) { i++; continue }
      return true
    }
    if (c >= 0xdc00 && c <= 0xdfff) return true
  }
  return false
}
// Whether text could pass part of itself to a neighbouring line of the signed
// message, or has no UTF-8 form of its own.
const unsafe = (v) => typeof v === 'string' && (v.includes('\n') || v.includes('\r') || hasLoneSurrogate(v))

// create(), except that for a label or model it must refuse this checks the
// refusal and gives null.
async function createChecked(opts) {
  if (unsafe(opts.label) || unsafe(opts.model)) {
    await assert.rejects(KxcoAgentIdentity.create(opts), KxcoPqAgentError)
    return null
  }
  return KxcoAgentIdentity.create(opts)
}

// The sponsor-signed message as the relay recomputes it, signed by `who`. Used
// to sign a credential the way an earlier version could, with a line break in
// a field.
async function signedAsBefore(c, who) {
  const msg = new TextEncoder().encode([
    'kxco-agent-credential-v1', c.agentKid, c.agentPublicKey, c.sponsorKid, c.agentType,
    c.label, c.model ?? '', canonicalize(c.scope), c.issuedAt, c.expiresAt,
  ].join('\n'))
  return { ...c, sponsorSignature: Buffer.from(await who.sponsor.sign(msg)).toString('base64url') }
}

function flipByte(b64url, at) {
  const bytes = Buffer.from(b64url, 'base64url')
  bytes[at % bytes.length] ^= 0x01
  return bytes.toString('base64url')
}

function reversedKeys(v) {
  if (Array.isArray(v)) return v.map(reversedKeys)
  if (v !== null && typeof v === 'object') {
    return Object.fromEntries(Object.keys(v).reverse().map((k) => [k, reversedKeys(v[k])]))
  }
  return v
}

// ── properties ──────────────────────────────────────────────────────────────

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('create then verify: any label, type, model and scope verifies under the sponsor key, and under no other; a label or model create() cannot sign is refused', async () => {
  await fc.assert(fc.asyncProperty(text, agentType, model, scope, expiresIn, async (label, type, mdl, sc, exp) => {
    const agent = await createChecked({ sponsor: A.sponsor, label, agentType: type, model: mdl, scope: sc, expiresIn: exp })
    if (!agent) return true
    const ok = await KxcoAgentIdentity.verify(agent.credential, { sponsorPublicKey: A.publicKey })
    const other = await KxcoAgentIdentity.verify(agent.credential, { sponsorPublicKey: B.publicKey })
    return ok.valid === true &&
      ok.agentKid === agent.kid && /^[0-9a-f]{16}$/.test(agent.kid) &&
      ok.sponsorKid === A.sponsor.kid &&
      ok.agentType === type &&
      ok.label === label &&
      ok.model === mdl &&
      canonicalize(ok.scope) === canonicalize(sc) &&
      new Date(ok.expiresAt) > new Date(ok.issuedAt) &&
      other.valid === false && other.error === 'sponsor signature invalid'
  }), SIGNING)
})

test('verify: changing any one signed field of a credential makes it fail', async () => {
  const changes = fc.record({ str: fc.string({ maxLength: 30 }), mdl: text, sc: scope, at: fc.nat() })
  await fc.assert(fc.asyncProperty(text, agentType, model, scope, changes, async (label, type, mdl, sc, c) => {
    const agent = await createChecked({ sponsor: A.sponsor, label, agentType: type, model: mdl, scope: sc, expiresIn: '30d' })
    if (!agent) return true
    const original = agent.credential
    const tampered = []

    for (const field of SIGNED_STRING_FIELDS) {
      tampered.push({ ...original, [field]: c.str === original[field] ? `${c.str}.` : c.str })
    }
    tampered.push({ ...original, model: c.mdl === original.model ? `${c.mdl}.` : c.mdl })
    if (original.model !== undefined) {
      const { model: _dropped, ...withoutModel } = original
      tampered.push(withoutModel)
    }
    tampered.push({ ...original, scope: canonicalize(c.sc) === canonicalize(original.scope) ? { ...c.sc, added: 1 } : c.sc })
    // A member named "__proto__" added to the signed scope, as JSON.parse would
    // leave it: an own key, not the prototype.
    const withProto = JSON.parse(JSON.stringify(original.scope))
    Object.defineProperty(withProto, '__proto__', { value: c.sc, enumerable: true, writable: true, configurable: true })
    tampered.push({ ...original, scope: withProto })
    tampered.push({ ...original, sponsorSignature: flipByte(original.sponsorSignature, c.at) })

    for (const credential of tampered) {
      const r = await KxcoAgentIdentity.verify(credential, { sponsorPublicKey: A.publicKey })
      if (r.valid !== false) return false
    }
    return true
  }), SIGNING)
})

test('verify: a label signed with a line break in it does not verify, however its text is split between neighbouring fields, and an unpaired surrogate cannot stand in for U+FFFD', async () => {
  const part = fc.string({ unit: 'grapheme', minLength: 1, maxLength: 12 }).filter((s) => !unsafe(s))
  await fc.assert(fc.asyncProperty(part, part, agentType, scope, async (head, tail, type, sc) => {
    const agent = await KxcoAgentIdentity.create({ sponsor: A.sponsor, label: head, agentType: type, scope: sc, expiresIn: '30d' })
    const earlier = await signedAsBefore({ ...agent.credential, label: `${head}\n${tail}` }, A)
    const replacement = await KxcoAgentIdentity.create({ sponsor: A.sponsor, label: `${head}\uFFFD`, agentType: type, scope: sc, expiresIn: '30d' })
    const presented = [
      earlier,
      { ...earlier, label: head, model: `${tail}\n` },
      { ...earlier, agentType: `${type}\n${head}`, label: tail },
      { ...replacement.credential, label: `${head}\uD800` },
    ]
    for (const credential of presented) {
      const r = await KxcoAgentIdentity.verify(credential, { sponsorPublicKey: A.publicKey })
      if (r.valid !== false) return false
    }
    return (await KxcoAgentIdentity.verify(replacement.credential, { sponsorPublicKey: A.publicKey })).valid === true
  }), SIGNING)
})

test('verify: a credential-shaped object the sponsor never signed does not verify', async () => {
  const future = new Date(Date.now() + 86_400_000).toISOString()
  const unsigned = fc.record({
    'kxco-agent': fc.constantFrom('1', '1', '2', ''),
    agentKid: fc.oneof(fc.stringMatching(/^[0-9a-f]{16}$/), fc.string()),
    agentPublicKey: fc.oneof(fc.uint8Array({ minLength: 1952, maxLength: 1952 }).map((b) => Buffer.from(b).toString('base64url')), fc.string()),
    sponsorKid: fc.constantFrom(A.sponsor.kid, 'aa29f37ab7f4b2cf'),
    agentType: fc.oneof(agentType, fc.string()),
    label: fc.string(),
    scope: anyJson,
    issuedAt: fc.constantFrom(new Date().toISOString()),
    expiresAt: fc.oneof(fc.constant(future), fc.string()),
    sponsorSignature: fc.oneof(fc.uint8Array({ minLength: 3309, maxLength: 3309 }), fc.uint8Array({ maxLength: 64 }))
      .map((b) => Buffer.from(b).toString('base64url')),
  })
  await fc.assert(fc.asyncProperty(unsigned, async (credential) => {
    const r = await KxcoAgentIdentity.verify(credential, { sponsorPublicKey: A.publicKey })
    return r.valid === false && typeof r.error === 'string'
  }), { numRuns: 100 })
})

test('verify without a sponsor key: a past expiresAt is refused, one that is not a date counts as expired, and a future one passes', async () => {
  const agent = await KxcoAgentIdentity.create({ sponsor: A.sponsor, label: 'expiry', agentType: 'process', scope: {}, expiresIn: '1d' })
  const now = Date.now()
  const past = fc.date({ min: new Date(0), max: new Date(now - 1000), noInvalidDate: true })
  const future = fc.date({ min: new Date(now + 3_600_000), max: new Date('2200-01-01T00:00:00Z'), noInvalidDate: true })
  const notADate = fc.string().filter((s) => s !== '' && Number.isNaN(new Date(s).getTime()))
  await fc.assert(fc.asyncProperty(past, future, notADate, async (p, f, n) => {
    const expired = await KxcoAgentIdentity.verify({ ...agent.credential, expiresAt: p.toISOString() })
    const current = await KxcoAgentIdentity.verify({ ...agent.credential, expiresAt: f.toISOString() })
    const unreadable = await KxcoAgentIdentity.verify({ ...agent.credential, expiresAt: n })
    return expired.valid === false && /expired/.test(expired.error) && current.valid === true &&
      unreadable.valid === false && /expired/.test(unreadable.error)
  }), { numRuns: 300 })
})

test('export then import: the restored identity is the same agent and signs as it', async () => {
  await fc.assert(fc.asyncProperty(text, agentType, model, scope, fc.uint8Array({ maxLength: 256 }), async (label, type, mdl, sc, msg) => {
    const agent = await createChecked({ sponsor: A.sponsor, label, agentType: type, model: mdl, scope: sc, expiresIn: '7d' })
    if (!agent) return true
    // Through JSON, as it would be stored.
    const loaded = await KxcoAgentIdentity.import(JSON.parse(JSON.stringify(agent.export())))
    const sig = await loaded.sign(msg)
    const again = await KxcoAgentIdentity.verify(loaded.credential, { sponsorPublicKey: A.publicKey })
    return loaded.kid === agent.kid &&
      loaded.sponsorKid === agent.sponsorKid &&
      loaded.label === label &&
      canonicalize(loaded.scope) === canonicalize(sc) &&
      canonicalize(loaded.credential) === canonicalize(agent.credential) &&
      // A new agent is ML-DSA-87 by default.
      loaded.alg === 'ML-DSA-87' &&
      mlDsa87.verify(await agent.getPublicKey(), msg, Buffer.from(sig).toString('hex')) === true &&
      again.valid === true
  }), SIGNING)
})

test('checkScope: never allows an action outside the scope, and names every limit it checked', () => {
  fc.assert(fc.property(scope, action, (sc, a) => {
    const d = checkScope(sc, a)
    if (typeof d.allowed !== 'boolean' || !Array.isArray(d.checked)) return false
    if (!d.allowed) return typeof d.reason === 'string'
    return permitted(sc, a) && configuredLimits(sc, a).every((name) => d.checked.includes(name))
  }), { numRuns: 5000 })
})

test('checkScope: allows an action that is inside every configured limit', () => {
  fc.assert(fc.property(scope, action, (sc, a) => {
    fc.pre(permitted(sc, a))
    return checkScope(sc, a).allowed === true
  }), { numRuns: 500 })
})

test('checkScope: on any scope-shaped value, allows an action only when the section it reads is well formed and the rules permit it', () => {
  fc.assert(fc.property(messyScope, action, (sc, a) => {
    if (!isPlainObject(sc)) {
      assert.throws(() => checkScope(sc, a), KxcoPqAgentError)
      return true
    }
    const d = checkScope(sc, a)
    if (!d.allowed) return typeof d.reason === 'string'
    return sectionSound(sc, a.type) && permitted(sc, a)
  }), { numRuns: 5000 })
})

test('checkScope: a capability the scope withholds or never mentions is refused, whatever the action carries', () => {
  const withheld = fc.constantFrom('omit', false, null, { enabled: false })
  const sectionOf = { payment: 'payments', attestation: 'attestations', auditLog: 'auditLog', credentials: 'credentials' }
  fc.assert(fc.property(scope, action, withheld, (sc, a, w) => {
    const s = { ...sc }
    if (w === 'omit') delete s[sectionOf[a.type]]
    else s[sectionOf[a.type]] = w
    const d = checkScope(s, a)
    return d.allowed === false && typeof d.reason === 'string'
  }), PURE)
})

test('checkScope: an action type outside the four is refused', () => {
  const type = fc.oneof(fc.string(), fc.integer(), fc.constantFrom(undefined, null, true)).filter((t) => !ACTION_TYPES.includes(t))
  fc.assert(fc.property(scope, action, type, (sc, a, t) => {
    const d = checkScope(sc, { ...a, type: t })
    return d.allowed === false && /unknown action type/.test(d.reason)
  }), PURE)
})

test('validateScope: accepts exactly the well-formed scopes, refuses the rest with KxcoPqAgentError, and what it accepts is enforced', () => {
  fc.assert(fc.property(messyScope, action, (sc, a) => {
    let accepted
    try {
      accepted = validateScope(sc)
    } catch (err) {
      return err instanceof KxcoPqAgentError && !(wellFormed(sc) && signable(sc))
    }
    if (accepted !== sc || !wellFormed(sc) || !signable(sc)) return false
    const d = checkScope(sc, a)
    return d.allowed === false || permitted(sc, a)
  }), PURE)
})

test('hashScope: 64 hex characters, the SHA-256 of the JCS form, whatever the key order, and a value JCS cannot sign is refused with KxcoPqAgentError', async () => {
  await fc.assert(fc.asyncProperty(fc.oneof(scope, anyJson), async (sc) => {
    if (!signable(sc)) {
      await assert.rejects(hashScope(sc), KxcoPqAgentError)
      return true
    }
    const h = await hashScope(sc)
    const expected = createHash('sha256').update(canonicalize(sc)).digest('hex')
    return /^[0-9a-f]{64}$/.test(h) &&
      h === expected &&
      h === await hashScope(reversedKeys(sc)) &&
      h === await hashScope(JSON.parse(JSON.stringify(sc)))
  }), { numRuns: 300 })
})
