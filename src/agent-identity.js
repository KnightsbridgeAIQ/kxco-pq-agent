import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { validateScope, hashScope } from './scope.js'
import { canonicalize }             from './jcs.js'
import { KxcoPqAgentError }         from './errors.js'
import { AgentChainClient }         from './agent-client.js'

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

function credentialSigningMsg({ agentKid, agentPublicKey, sponsorKid, agentType, label, model, scope, issuedAt, expiresAt }) {
  return enc.encode([
    'kxco-agent-credential-v1',
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

const VALID_AGENT_TYPES = new Set(['llm', 'robot', 'iot', 'process'])

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
   */
  static async create({ sponsor, label, agentType, model, scope, expiresIn, chain } = {}) {
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

    validateScope(scope)

    const keypair      = mlDsa.ml_dsa65.keygen()
    const agentKid     = fingerprint(keypair.publicKey)
    const agentPubB64  = b64url(keypair.publicKey)
    const issuedAt     = new Date().toISOString()
    const expiresAt    = new Date(Date.now() + parseDuration(expiresIn)).toISOString()

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
    })

    const sigBytes   = await sponsor.sign(sigMsg)
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
    return mlDsa.ml_dsa65.sign(
      new Uint8Array(this.#keypair.secretKey),
      new Uint8Array(message),
    )
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
   * Pass sponsorPublicKey (Uint8Array) to perform full ML-DSA-65 signature verification.
   * Without it, only expiry and format are checked.
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

    if (new Date(expiresAt) < new Date()) {
      return { valid: false, error: 'agent credential has expired' }
    }

    if (sponsorPublicKey) {
      const msg = credentialSigningMsg({ agentKid, agentPublicKey, sponsorKid, agentType, label, model, scope, issuedAt, expiresAt })
      let ok
      try {
        ok = mlDsa.ml_dsa65.verify(new Uint8Array(sponsorPublicKey), msg, fromB64url(sponsorSignature))
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
    await chain.revokeAgentCredential({ agentKid, reason })
  }
}
