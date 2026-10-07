import { fingerprint } from 'kxco-post-quantum'
import { validateScope, hashScope } from './scope.js'
import { canonicalize }             from './jcs.js'
import { KxcoPqAgentError }         from './errors.js'
import { AgentChainClient }         from './agent-client.js'
import { SETS, DEFAULT_ALG, V1_ALG, algForPublicKey, algForSecretKey, statedAlg } from './alg.js'

const CREDENTIAL_VERSION = '1'
const IDENTITY_VERSION   = '1'

const enc = new TextEncoder()

function b64url(bytes) {
  return Buffer.from(bytes).toString('base64url')
}

function fromB64url(s) {
  return new Uint8Array(Buffer.from(s, 'base64url'))
}

function parseDuration(val) {
  if (typeof val === 'number') return val * 1000
  const m = String(val).match(/^(\d+)(d|h|m|s|y)$/)
  if (!m) throw new KxcoPqAgentError(`invalid expiresIn '${val}' — use '30d', '1y', or seconds as a number`)
  const n  = parseInt(m[1], 10)
  const ms = { d: 86400000, h: 3600000, m: 60000, s: 1000, y: 31536000000 }
  return n * ms[m[2]]
}

// An ML-DSA-65 sponsor signs the v1 message, exactly as before. An ML-DSA-87
// sponsor signs v1.1, whose first line differs and whose second line is the
// sponsor's algorithm, so the algorithm is inside the signed bytes.
function credentialSigningMsg({ agentKid, agentPublicKey, sponsorKid, agentType, label, model, scope, issuedAt, expiresAt, sponsorAlg = null }) {
  return enc.encode([
    ...(sponsorAlg === null ? ['kxco-agent-credential-v1'] : ['kxco-agent-credential-v1.1', sponsorAlg]),
    agentKid,
    agentPublicKey,
    sponsorKid,
    agentType,
    label,
    model ?? '',
    canonicalize(scope),
    issuedAt,
    expiresAt,
  ].join('\n'))
}

// The sponsor-signed message is one field per line, so a field carrying a
// line break could hand part of its text to its neighbour, and two different
// credentials would sign the same bytes. An unpaired surrogate has no UTF-8
// form (TextEncoder writes every one as U+FFFD), so it is refused as well.
const UNSAFE_FIELD = /[\r\n]|\p{Cs}/u

// Why the first of these fields cannot go into the message, or null.
function fieldFault(fields) {
  for (const [name, value] of Object.entries(fields)) {
    let text
    try {
      text = value == null ? '' : `${value}`
    } catch {
      return `${name} cannot be written as text`
    }
    if (UNSAFE_FIELD.test(text)) return `${name} must not contain a line break or an unpaired surrogate`
  }
  return null
}

const VALID_AGENT_TYPES = new Set(['llm', 'robot', 'iot', 'process'])

// The sponsor's parameter set. Its key decides where the sponsor exposes one
// (publicKeyHex, as a kxco-pq-sdk KxcoIdentity does, or getPublicKey()); a
// stated `alg` is for a sponsor that exposes neither, and one that disagrees
// with the key is refused. A sponsor that exposes nothing is an existing key
// read as v1, ML-DSA-65; the signature-length check in create() refuses it if
// it is not.
async function sponsorAlgOf(sponsor) {
  if (sponsor.alg !== undefined && !Object.hasOwn(SETS, sponsor.alg)) {
    throw new KxcoPqAgentError(`create: sponsor.alg must be 'ML-DSA-65' or 'ML-DSA-87', got ${JSON.stringify(sponsor.alg)}`)
  }
  let key = null
  if (typeof sponsor.publicKeyHex === 'string') key = Buffer.from(sponsor.publicKeyHex, 'hex')
  else if (typeof sponsor.getPublicKey === 'function') key = await sponsor.getPublicKey()
  const keyAlg = key ? algForPublicKey(key) : null
  if (sponsor.alg !== undefined && keyAlg !== null && sponsor.alg !== keyAlg) {
    throw new KxcoPqAgentError(`create: sponsor.alg is ${sponsor.alg} but the sponsor's public key is ${keyAlg}`)
  }
  return keyAlg ?? sponsor.alg ?? V1_ALG
}

export class KxcoAgentIdentity {
  #kid
  #keypair
  #sponsorKid
  #agentType
  #label
  #model
  #scope
  #issuedAt
  #expiresAt
  #credential

  constructor(opts) {
    this.#kid        = opts.kid
    this.#keypair    = opts.keypair
    this.#sponsorKid = opts.sponsorKid
    this.#agentType  = opts.agentType
    this.#label      = opts.label
    this.#model      = opts.model ?? null
    this.#scope      = opts.scope
    this.#issuedAt   = opts.issuedAt
    this.#expiresAt  = opts.expiresAt
    this.#credential = opts.credential
  }

  get kid()        { return this.#kid }
  get sponsorKid() { return this.#sponsorKid }
  get agentType()  { return this.#agentType }
  get label()      { return this.#label }
  get model()      { return this.#model }
  get scope()      { return JSON.parse(JSON.stringify(this.#scope)) }
  get issuedAt()   { return this.#issuedAt }
  get expiresAt()  { return this.#expiresAt }
  get credential() { return JSON.parse(JSON.stringify(this.#credential)) }

  /** This agent's ML-DSA parameter set, 'ML-DSA-65' or 'ML-DSA-87', read from its key. */
  get alg() { return algForPublicKey(this.#keypair?.publicKey) ?? V1_ALG }

  // ── Factory ───────────────────────────────────────────────────────────────

  /**
   * Create a new agent identity. Any KxcoIdentity holder may sponsor an agent.
   *
   * @param {object} opts
   * @param {{ kid: string, sign(msg: Uint8Array): Promise<Uint8Array> }} opts.sponsor
   * @param {string} opts.label       — human-readable name for this agent
   * @param {'llm'|'robot'|'iot'|'process'} opts.agentType
   * @param {string} [opts.model]     — model/hardware identifier (optional)
   * @param {object} opts.scope       — locked capability manifest (see scope.js)
   * @param {string|number} opts.expiresIn — '30d', '1y', or seconds as number (mandatory)
   * @param {object} [opts.chain]     — KxcoChain instance for on-chain registration
   * @param {'ML-DSA-87'|'ML-DSA-65'} [opts.alg] the agent key's parameter set; default ML-DSA-87
   */
  static async create({ sponsor, label, agentType, model, scope, expiresIn, chain, alg } = {}) {
    if (!sponsor?.kid || typeof sponsor.sign !== 'function') {
      throw new KxcoPqAgentError('create: sponsor must have .kid and .sign(message)')
    }
    if (!label)                       throw new KxcoPqAgentError('create: label is required')
    if (!agentType)                   throw new KxcoPqAgentError('create: agentType is required')
    if (!VALID_AGENT_TYPES.has(agentType)) {
      throw new KxcoPqAgentError(`create: agentType must be one of: ${[...VALID_AGENT_TYPES].join(', ')}`)
    }
    if (!scope)                       throw new KxcoPqAgentError('create: scope is required')
    if (expiresIn == null)            throw new KxcoPqAgentError('create: expiresIn is required — agents must have an expiry')

    const fault = fieldFault({ label, model, sponsorKid: sponsor.kid })
    if (fault) throw new KxcoPqAgentError(`create: ${fault}`)

    validateScope(scope)

    if (alg !== undefined && !Object.hasOwn(SETS, alg)) {
      throw new KxcoPqAgentError(`create: alg must be 'ML-DSA-65' or 'ML-DSA-87', got ${JSON.stringify(alg)}`)
    }
    const sponsorAlg = await sponsorAlgOf(sponsor)

    // Random keygen has no wrapper equivalent; the raw keygen is reached
    // through the wrapper's own re-export, as ML-DSA-65 always has been.
    const keypair      = SETS[alg ?? DEFAULT_ALG].keygen()
    const agentKid     = fingerprint(keypair.publicKey)
    const agentPubB64  = b64url(keypair.publicKey)
    const issuedAt     = new Date().toISOString()
    const expiry       = new Date(Date.now() + parseDuration(expiresIn))
    if (Number.isNaN(expiry.getTime())) {
      throw new KxcoPqAgentError(`create: expiresIn '${expiresIn}' does not give a representable expiry date`)
    }
    const expiresAt    = expiry.toISOString()

    const sigMsg = credentialSigningMsg({
      agentKid,
      agentPublicKey: agentPubB64,
      sponsorKid:     sponsor.kid,
      agentType,
      label,
      model,
      scope,
      issuedAt,
      expiresAt,
      sponsorAlg: sponsorAlg === V1_ALG ? null : sponsorAlg,
    })

    const sigBytes   = await sponsor.sign(sigMsg)
    // A sponsor that signed with a key of another set from the one it was
    // read as would produce a credential nothing can verify. Refused here.
    if (sigBytes?.length !== SETS[sponsorAlg].signatureBytes) {
      throw new KxcoPqAgentError(
        `create: the sponsor's signature is not ${sponsorAlg}; give the sponsor publicKeyHex, getPublicKey() or alg`,
      )
    }
    const credential = {
      'kxco-agent':     CREDENTIAL_VERSION,
      agentKid,
      agentPublicKey:   agentPubB64,
      sponsorKid:       sponsor.kid,
      agentType,
      label,
      ...(model && { model }),
      scope,
      issuedAt,
      expiresAt,
      // Recorded only for an ML-DSA-87 sponsor, so an ML-DSA-65 credential
      // keeps exactly the v1 shape.
      ...(sponsorAlg !== V1_ALG && { sponsorAlg }),
      sponsorSignature: b64url(sigBytes),
    }

    if (chain) {
      const scopeHash    = await hashScope(scope)
      const expiresAtSec = Math.floor(new Date(expiresAt).getTime() / 1000)
      await chain.issueAgentCredential({
        agentKid,
        agentPublicKeyHex: Buffer.from(keypair.publicKey).toString('hex'),
        agentType,
        scopeHash,
        expiresAt: expiresAtSec,
      })
    }

    return new KxcoAgentIdentity({
      kid:        agentKid,
      keypair,
      sponsorKid: sponsor.kid,
      agentType,
      label,
      model:      model ?? null,
      scope,
      issuedAt,
      expiresAt,
      credential,
    })
  }

  // ── Signing ───────────────────────────────────────────────────────────────

  async sign(message) {
    if (!this.#keypair?.secretKey) {
      throw new KxcoPqAgentError('no signing key — reconstruct with KxcoAgentIdentity.import()')
    }
    // The secret key decides which set signs.
    const alg = algForSecretKey(this.#keypair.secretKey)
    if (alg === null) throw new KxcoPqAgentError('the secret key is neither ML-DSA-65 nor ML-DSA-87')
    return Buffer.from(SETS[alg].module.sign(
      new Uint8Array(this.#keypair.secretKey),
      new Uint8Array(message),
    ), 'hex')
  }

  async getPublicKey() {
    return this.#keypair.publicKey
  }

  // ── Export / import ───────────────────────────────────────────────────────

  export() {
    return {
      'kxco-agent-identity': IDENTITY_VERSION,
      kid:        this.#kid,
      sponsorKid: this.#sponsorKid,
      agentType:  this.#agentType,
      label:      this.#label,
      ...(this.#model && { model: this.#model }),
      scope:      this.#scope,
      issuedAt:   this.#issuedAt,
      expiresAt:  this.#expiresAt,
      secretKey:  b64url(this.#keypair.secretKey),
      publicKey:  b64url(this.#keypair.publicKey),
      credential: this.#credential,
    }
  }

  static async import(exported) {
    if (!exported || exported['kxco-agent-identity'] !== IDENTITY_VERSION) {
      throw new KxcoPqAgentError('import: invalid or unsupported agent identity format')
    }
    // The restored agent acts on this scope, so it is held to the rules
    // create() applied.
    validateScope(exported.scope)
    return new KxcoAgentIdentity({
      kid:        exported.kid,
      keypair:    { secretKey: fromB64url(exported.secretKey), publicKey: fromB64url(exported.publicKey) },
      sponsorKid: exported.sponsorKid,
      agentType:  exported.agentType,
      label:      exported.label,
      model:      exported.model ?? null,
      scope:      exported.scope,
      issuedAt:   exported.issuedAt,
      expiresAt:  exported.expiresAt,
      credential: exported.credential,
    })
  }

  // ── Chain client ──────────────────────────────────────────────────────────

  /**
   * Returns an AgentChainClient that sends agent-signed intents to the relay.
   * Each request automatically includes this agent's credential and kid.
   * @param {string} relay — relay base URL, e.g. 'https://relay.kxco.ai'
   * @param {{ timeout?: number }} [opts]
   */
  toChainClient(relay, { timeout } = {}) {
    return new AgentChainClient({ relay, agent: this, ...(timeout && { timeout }) })
  }

  // ── Static: verify a credential ──────────────────────────────────────────

  /**
   * Verify an agent credential envelope.
   * Pass sponsorPublicKey (Uint8Array) to perform full ML-DSA signature verification.
   * Without it, only expiry and format are checked.
   *
   * The sponsor key decides the algorithm. A credential with no `sponsorAlg`
   * is v1 and means ML-DSA-65; one stating the other set from the key is
   * refused rather than tried.
   *
   * @param {object} credential
   * @param {{ sponsorPublicKey?: Uint8Array }} [opts]
   */
  static async verify(credential, { sponsorPublicKey } = {}) {
    if (!credential || credential['kxco-agent'] !== CREDENTIAL_VERSION) {
      return { valid: false, error: 'invalid or unsupported credential format' }
    }

    const {
      agentKid, agentPublicKey, sponsorKid, agentType,
      label, model, scope, issuedAt, expiresAt, sponsorSignature,
    } = credential

    if (!agentKid || !agentPublicKey || !sponsorKid || !agentType || !issuedAt || !expiresAt || !sponsorSignature) {
      return { valid: false, error: 'malformed credential — missing required fields' }
    }

    const fault = fieldFault({ agentKid, agentPublicKey, sponsorKid, agentType, label, model, issuedAt, expiresAt })
    if (fault) return { valid: false, error: `malformed credential: ${fault}` }

    // The scope is returned for the caller to act on, so it is held to the
    // rules create() applied. That also means it has a JCS form to check the
    // signature over.
    try {
      validateScope(scope)
    } catch (err) {
      return { valid: false, error: `malformed credential: ${err.message}` }
    }

    // An expiry that is not a date cannot be shown to lie in the future.
    const expiry = new Date(expiresAt).getTime()
    if (Number.isNaN(expiry)) {
      return { valid: false, error: 'agent credential has no valid expiry, so it is treated as expired' }
    }
    if (expiry < Date.now()) {
      return { valid: false, error: 'agent credential has expired' }
    }

    if (sponsorPublicKey) {
      const stated = statedAlg(credential.sponsorAlg)
      const alg    = stated ?? V1_ALG
      const keyAlg = algForPublicKey(sponsorPublicKey)
      if (keyAlg !== null && keyAlg !== alg) {
        return { valid: false, error: 'sponsor algorithm does not match key' }
      }
      const msg = credentialSigningMsg({
        agentKid, agentPublicKey, sponsorKid, agentType, label, model, scope, issuedAt, expiresAt, sponsorAlg: stated,
      })
      let ok
      try {
        ok = keyAlg !== null &&
          SETS[alg].module.verify(new Uint8Array(sponsorPublicKey), msg, Buffer.from(fromB64url(sponsorSignature)).toString('hex'))
      } catch {
        ok = false
      }
      if (!ok) return { valid: false, error: 'sponsor signature invalid' }
    }

    return {
      valid: true,
      agentKid,
      sponsorKid,
      agentType,
      label,
      ...(model && { model }),
      scope,
      issuedAt,
      expiresAt,
    }
  }

  // ── Static: revoke on-chain ───────────────────────────────────────────────

  /**
   * Revoke an agent credential on-chain.
   * The chain parameter must be a KxcoChain instance belonging to the sponsor.
   *
   * @param {string} agentKid
   * @param {{ chain: object, reason?: string }} opts
   */
  static async revoke(agentKid, { chain, reason = '' } = {}) {
    if (!agentKid) throw new KxcoPqAgentError('revoke: agentKid is required')
    if (!chain)    throw new KxcoPqAgentError('revoke: chain is required for on-chain revocation')
    return chain.revokeAgentCredential({ agentKid, reason })
  }
}
