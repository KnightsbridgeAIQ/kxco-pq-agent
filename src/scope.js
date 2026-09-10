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

  if (auditLog != null && typeof auditLog !== 'boolean' && (typeof auditLog !== 'object' || Array.isArray(auditLog))) {
    throw new KxcoPqAgentError('scope.auditLog must be a boolean or object')
  }

  if (credentials != null && typeof credentials !== 'boolean' && (typeof credentials !== 'object' || Array.isArray(credentials))) {
    throw new KxcoPqAgentError('scope.credentials must be a boolean or object')
  }

  return scope
}

/**
 * Decide whether a scope permits an action, before it is attempted.
 *
 * The relay enforces scope too, and that enforcement is the one that binds: it
 * sits behind the agent, so a compromised agent cannot talk its way past it.
 * This check runs in front, on the same signed scope, and it earns its place
 * three ways. It refuses offline, so an agent that cannot reach the relay still
 * knows what it may not do. It refuses immediately, without spending a network
 * round trip to be told no. And it names the limit that stopped it, which a
 * remote refusal cannot do as precisely.
 *
 * Fails closed throughout. A capability the scope does not grant is denied, an
 * action type it does not recognise is denied, and a configured limit that
 * cannot be evaluated from the inputs given is denied rather than skipped.
 *
 * @param {object} scope — the signed capability manifest
 * @param {object} action
 * @param {'payment'|'attestation'|'auditLog'|'credentials'} action.type
 * @param {number}  [action.amount]      — payment only, ARMR
 * @param {string}  [action.recipient]   — payment only, EVM address or kid
 * @param {number}  [action.spentToday]  — payment only, required when
 *   `payments.maxPerDay` is set, because a day cap cannot be judged from one
 *   transaction
 * @param {string}  [action.purpose]     — attestation only
 * @returns {{ allowed: boolean, reason?: string, checked: string[] }}
 */
export function checkScope(scope, action) {
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) {
    throw new KxcoPqAgentError('checkScope: scope must be a plain object')
  }
  if (!action || typeof action !== 'object' || Array.isArray(action)) {
    throw new KxcoPqAgentError('checkScope: action must be a plain object')
  }

  const checked = []
  const deny  = (reason) => ({ allowed: false, reason, checked })
  const allow = ()       => ({ allowed: true, checked })

  const granted = (section) =>
    section != null && section !== false && section.enabled !== false

  switch (action.type) {
    case 'payment': {
      const p = scope.payments
      checked.push('payments.enabled')
      if (!granted(p)) return deny('scope does not grant payments')

      if (typeof action.amount !== 'number' || !(action.amount > 0)) {
        return deny('payment amount must be a positive number')
      }

      if (p.maxPerTransaction !== undefined) {
        checked.push('payments.maxPerTransaction')
        if (action.amount > p.maxPerTransaction) {
          return deny(
            `amount ${action.amount} exceeds maxPerTransaction ${p.maxPerTransaction}`,
          )
        }
      }

      if (p.maxPerDay !== undefined) {
        checked.push('payments.maxPerDay')
        if (typeof action.spentToday !== 'number' || action.spentToday < 0) {
          return deny(
            'payments.maxPerDay is set, so spentToday is required to evaluate it',
          )
        }
        if (action.spentToday + action.amount > p.maxPerDay) {
          return deny(
            `amount ${action.amount} would take today's total to ` +
            `${action.spentToday + action.amount}, past maxPerDay ${p.maxPerDay}`,
          )
        }
      }

      if (p.allowedRecipients !== undefined) {
        checked.push('payments.allowedRecipients')
        if (typeof action.recipient !== 'string') {
          return deny('payments.allowedRecipients is set, so a recipient is required')
        }
        // EVM addresses are case-insensitive; kids are lowercase hex.
        const want = action.recipient.toLowerCase()
        const ok = p.allowedRecipients.some((r) => r.toLowerCase() === want)
        if (!ok) return deny(`recipient ${action.recipient} is not in allowedRecipients`)
      }

      return allow()
    }

    case 'attestation': {
      const a = scope.attestations
      checked.push('attestations.enabled')
      if (!granted(a)) return deny('scope does not grant attestations')

      if (a.purposes !== undefined) {
        checked.push('attestations.purposes')
        if (typeof action.purpose !== 'string') {
          return deny('attestations.purposes is set, so a purpose is required')
        }
        if (!a.purposes.includes(action.purpose)) {
          return deny(`purpose '${action.purpose}' is not in attestations.purposes`)
        }
      }
      return allow()
    }

    case 'auditLog':
      checked.push('auditLog')
      return granted(scope.auditLog) ? allow() : deny('scope does not grant auditLog')

    case 'credentials':
      checked.push('credentials')
      return granted(scope.credentials)
        ? allow()
        : deny('scope does not grant credentials')

    default:
      return deny(`unknown action type '${action.type}'`)
  }
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
