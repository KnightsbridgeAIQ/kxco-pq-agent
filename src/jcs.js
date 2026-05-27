// RFC 8785 JSON Canonicalization Scheme (JCS), subset.
// Copied from kxco-pq-cli/src/jcs.js — do not diverge.

/**
 * Canonicalize a JSON-serializable value per (a subset of) RFC 8785.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  return JSON.stringify(walk(value))
}

function walk(v) {
  if (v === null) return null
  if (typeof v === 'boolean') return v
  if (typeof v === 'string')  return v
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new TypeError('JCS: non-finite numbers are not representable in JSON')
    if (!Number.isInteger(v)) throw new TypeError('JCS subset: floats are not supported')
    return v
  }
  if (Array.isArray(v)) return v.map(walk)
  if (v && typeof v === 'object') {
    const out = {}
    for (const k of Object.keys(v).sort()) {
      const child = walk(v[k])
      if (child === undefined) continue
      out[k] = child
    }
    return out
  }
  if (v === undefined) return undefined
  throw new TypeError(`JCS: unsupported value of type ${typeof v}`)
}
