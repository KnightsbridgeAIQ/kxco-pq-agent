import { KxcoPqAgentError } from './errors.js'
import { canonicalize }     from './jcs.js'

const EVM_RE = /^0x[0-9a-fA-F]{40}$/
const KID_RE = /^[0-9a-f]{16}$/

function validRecipient(s) {
  return EVM_RE.test(s) || KID_RE.test(s)
}

/**
 * Validate a scope object. Throws KxcoPqAgentError on any violation.
 * Returns the scope unchanged.
 */
export function validateScope(scope) {
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) {
    throw new KxcoPqAgentError('scope must be a plain object')
  }

  const { payments, attestations, auditLog, credentials } = scope

  if (payments != null) {
    if (typeof payments !== 'object' || Array.isArray(payments)) {
      throw new KxcoPqAgentError('scope.payments must be an object')
    }
    if (payments.enabled !== false) {
      const { maxPerTransaction: mpt, maxPerDay: mpd, allowedRecipients: ar } = payments

      if (mpt !== undefined) {
        if (typeof mpt !== 'number' || mpt <= 0) {
          throw new KxcoPqAgentError('scope.payments.maxPerTransaction must be a positive number')
        }
      }
      if (mpd !== undefined) {
        if (typeof mpd !== 'number' || mpd <= 0) {
          throw new KxcoPqAgentError('scope.payments.maxPerDay must be a positive number')
        }
      }
      if (mpt !== undefined && mpd !== undefined && mpt > mpd) {
        throw new KxcoPqAgentError('scope.payments.maxPerTransaction must not exceed maxPerDay')
      }
      if (ar !== undefined) {
        if (!Array.isArray(ar)) {
          throw new KxcoPqAgentError('scope.payments.allowedRecipients must be an array')
        }
        for (const r of ar) {
          if (!validRecipient(r)) {
            throw new KxcoPqAgentError(
              `invalid recipient '${r}' — must be an EVM address (0x + 40 hex) or KXCO kid (16 lowercase hex chars)`
            )
          }
        }
      }
    }
  }

  if (attestations != null) {
    if (typeof attestations !== 'object' || Array.isArray(attestations)) {
      throw new KxcoPqAgentError('scope.attestations must be an object')
    }
    if (attestations.enabled !== false && attestations.purposes !== undefined) {
      if (!Array.isArray(attestations.purposes)) {
        throw new KxcoPqAgentError('scope.attestations.purposes must be an array of strings')
      }
      for (const p of attestations.purposes) {
        if (typeof p !== 'string' || !p.trim()) {
          throw new KxcoPqAgentError('each entry in scope.attestations.purposes must be a non-empty string')
        }
      }
    }
  }

  if (auditLog != null && (typeof auditLog !== 'object' || Array.isArray(auditLog))) {
    throw new KxcoPqAgentError('scope.auditLog must be an object')
  }

  if (credentials != null && (typeof credentials !== 'object' || Array.isArray(credentials))) {
    throw new KxcoPqAgentError('scope.credentials must be an object')
  }

  return scope
}

/**
 * Compute a hex SHA-256 of the JCS-canonical scope.
 * This hash is stored on-chain so the relay can verify scope integrity.
 * @param {object} scope
 * @returns {Promise<string>} 64-char hex string
 */
export async function hashScope(scope) {
  const bytes = new TextEncoder().encode(canonicalize(scope))
  const buf   = await globalThis.crypto.subtle.digest('SHA-256', bytes)
  return Buffer.from(buf).toString('hex')
}
