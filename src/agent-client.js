import { KxcoPqAgentError } from './errors.js'
import { canonicalize }     from './jcs.js'

const enc = new TextEncoder()

function randomNonce() {
  const bytes = new Uint8Array(32)
  globalThis.crypto.getRandomValues(bytes)
  return Buffer.from(bytes).toString('hex')
}

async function sha256Hex(str) {
  const buf = await globalThis.crypto.subtle.digest('SHA-256', enc.encode(str))
  return Buffer.from(buf).toString('hex')
}

// Each header is one line, so a field carrying a line break could pass for the
// end of one header and the start of the next, and two different intents would
// sign the same bytes. An unpaired surrogate has no UTF-8 form: TextEncoder
// writes every one as U+FFFD, so it is refused for the same reason. JSON
// escapes both inside the payload, so only the header fields need the check.
const UNSAFE_HEADER = /[\r\n]|\p{Cs}/u

function header(name, value) {
  const text = `${value}`
  if (UNSAFE_HEADER.test(text)) {
    throw new KxcoPqAgentError(
      `${name} must not contain a line break or an unpaired surrogate`,
      { code: 'BAD_ARGUMENT' },
    )
  }
  return `${name}: ${text}`
}

function buildSigningMessage(operation, agentKid, sponsorKid, nonce, timestamp, credentialHash, payload) {
  return enc.encode([
    'kxco-relay-agent-v1',
    header('operation', operation),
    header('agentKid', agentKid),
    header('sponsorKid', sponsorKid),
    header('nonce', nonce),
    header('timestamp', timestamp),
    header('credentialHash', credentialHash),
    `payload: ${canonicalize(payload)}`,
  ].join('\n'))
}

/**
 * AgentChainClient — relay client for KxcoAgentIdentity.
 *
 * Sends ML-DSA-65 signed intents to the KXCO relay's /agent-intents endpoint.
 * Each request includes the agent's signed credential so the relay can verify
 * the sponsor's authorisation and enforce scope.
 *
 * Returned by KxcoAgentIdentity.toChainClient().
 */
export class AgentChainClient {
  #relay
  #agent
  #timeout
  #credentialB64
  #credentialHash  // lazy, cached after first use

  constructor({ relay, agent, timeout = 10_000 }) {
    if (!relay) throw new KxcoPqAgentError('relay URL is required', { code: 'BAD_CONFIG' })
    if (typeof relay !== 'string') throw new KxcoPqAgentError('relay must be a URL string', { code: 'BAD_CONFIG' })
    if (!agent) throw new KxcoPqAgentError('agent is required',     { code: 'BAD_CONFIG' })
    this.#relay          = relay.replace(/\/$/, '')
    this.#agent          = agent
    this.#timeout        = timeout
    this.#credentialB64  = Buffer.from(JSON.stringify(agent.credential)).toString('base64')
    this.#credentialHash = null
  }

  async #getCredentialHash() {
    if (!this.#credentialHash) {
      this.#credentialHash = await sha256Hex(this.#credentialB64)
    }
    return this.#credentialHash
  }

  // ── Operations ───────────────────────────────────────────────────────────

  /** Anchor an attestation envelope hash on-chain (requires scope.attestations.enabled). */
  async anchorAttestation({ payloadHash, purpose }) {
    return this.#send('anchorAttestation', { payloadHash, purpose })
  }

  /** Anchor an audit log checkpoint on-chain (requires scope.auditLog.enabled). */
  async anchorAuditRoot({ rootHash, entryCount }) {
    return this.#send('anchorAuditRoot', { rootHash, entryCount })
  }

  /**
   * Submit a payment intent (requires scope.payments.enabled).
   * The relay enforces allowedRecipients, maxPerTransaction, and maxPerDay.
   * @param {object} opts
   * @param {string} opts.to     — EVM address or KXCO kid of the recipient
   * @param {number} opts.amount — amount in ARMR
   */
  async transfer({ to, amount }) {
    return this.#send('transfer', { to, amount })
  }

  // ── Internal ─────────────────────────────────────────────────────────────

  async #send(operation, payload) {
    const nonce          = randomNonce()
    const timestamp      = Math.floor(Date.now() / 1000)
    const credentialHash = await this.#getCredentialHash()
    const agentKid       = this.#agent.kid
    const sponsorKid     = this.#agent.sponsorKid

    const msg      = buildSigningMessage(operation, agentKid, sponsorKid, nonce, timestamp, credentialHash, payload)
    const sigBytes = await this.#agent.sign(msg)
    const signature = Buffer.from(sigBytes).toString('hex')

    const intent = {
      operation,
      agentKid,
      sponsorKid,
      agentCredential: this.#credentialB64,
      credentialHash,
      nonce,
      timestamp,
      payload,
      signature,
    }

    const ac  = new AbortController()
    const tid = setTimeout(() => ac.abort(), this.#timeout)

    let response
    try {
      response = await fetch(`${this.#relay}/agent-intents`, {
        method:  'POST',
        headers: { 'content-type': 'application/json' },
        body:    JSON.stringify(intent),
        signal:  ac.signal,
      })
    } catch (err) {
      clearTimeout(tid)
      if (err.name === 'AbortError') {
        throw new KxcoPqAgentError(`relay request timed out after ${this.#timeout}ms`, { code: 'TIMEOUT' })
      }
      throw new KxcoPqAgentError(`relay request failed: ${err.message}`, { code: 'NETWORK_ERROR' })
    }
    clearTimeout(tid)

    let body
    try {
      body = await response.json()
    } catch {
      throw new KxcoPqAgentError('relay returned non-JSON response', { code: 'PARSE_ERROR', status: response.status })
    }

    if (!response.ok || body.ok === false) {
      throw new KxcoPqAgentError(
        body.error ?? `relay error ${response.status}`,
        { code: body.code ?? 'RELAY_ERROR' }
      )
    }

    return { txHash: body.txHash, blockNumber: body.blockNumber }
  }
}
