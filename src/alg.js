import { mlDsa, mlDsa87 } from 'kxco-post-quantum'

// The two ML-DSA parameter sets an agent or a sponsor can hold. The KEY decides
// which one is in play: a key's length names its set. A new agent key is
// ML-DSA-87 unless the caller asks for ML-DSA-65. ML-DSA-65 is the only set a
// v1 message, credential or intent ever meant, and that does not change.
export const SETS = Object.freeze({
  'ML-DSA-65': Object.freeze({
    module: mlDsa, keygen: () => mlDsa.ml_dsa65.keygen(),
    publicKeyBytes: 1952, secretKeyBytes: 4032, signatureBytes: 3309,
  }),
  'ML-DSA-87': Object.freeze({
    module: mlDsa87, keygen: () => mlDsa87.ml_dsa87.keygen(),
    publicKeyBytes: 2592, secretKeyBytes: 4896, signatureBytes: 4627,
  }),
})

/** The set a new agent key gets when `alg` is not given. */
export const DEFAULT_ALG = 'ML-DSA-87'

/**
 * The set a v1 message, credential or intent means. A record or key that names
 * no set is read as this one, so everything made before ML-DSA-87 existed here
 * keeps verifying. It is not the default for a new key.
 */
export const V1_ALG = 'ML-DSA-65'

/** The set a public key of this length belongs to, or null for neither. */
export function algForPublicKey(key) {
  for (const [name, set] of Object.entries(SETS)) if (key?.length === set.publicKeyBytes) return name
  return null
}

/** The set a secret key of this length belongs to, or null for neither. */
export function algForSecretKey(key) {
  for (const [name, set] of Object.entries(SETS)) if (key?.length === set.secretKeyBytes) return name
  return null
}

/**
 * A stated algorithm this package reads, or null. Null means the record is v1,
 * which means ML-DSA-65: that is how everything made before the field existed
 * reads.
 */
export function statedAlg(value) {
  return Object.hasOwn(SETS, value) ? value : null
}
