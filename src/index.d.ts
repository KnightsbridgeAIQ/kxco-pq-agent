// kxco-pq-agent — AI agent and robot identity for the KXCO PQ stack

// ── Error ────────────────────────────────────────────────────────────────────

export class KxcoPqAgentError extends Error {
  name: 'KxcoPqAgentError'
  code: string
}

// ── Scope ────────────────────────────────────────────────────────────────────

export interface PaymentScope {
  enabled:             boolean
  maxPerTransaction?:  number   // ARMR; must be ≤ maxPerDay
  maxPerDay?:          number   // ARMR
  /**
   * Allowed recipients — EVM addresses (0x + 40 hex) or KXCO kids (16 lowercase hex).
   * Empty array = locked to that empty whitelist (no payments allowed).
   * Absent / undefined = any recipient.
   */
  allowedRecipients?:  string[]
  currency?:           string   // e.g. 'ARMR'
}

export interface AttestationScope {
  enabled:   boolean
  /** Allowed purposes. Empty array = any purpose. */
  purposes?: string[]
}

export interface AgentScope {
  payments?:     PaymentScope
  attestations?: AttestationScope
  auditLog?:     { enabled: boolean }
  credentials?:  { enabled: boolean }
}

export function validateScope(scope: AgentScope): AgentScope
export function hashScope(scope: AgentScope): Promise<string>

// ── Credential envelope ───────────────────────────────────────────────────────

export interface AgentCredential {
  'kxco-agent':     string
  agentKid:         string
  agentPublicKey:   string   // base64url ML-DSA-65 public key
  sponsorKid:       string
  agentType:        'llm' | 'robot' | 'iot' | 'process'
  label:            string
  model?:           string
  scope:            AgentScope
  issuedAt:         string   // ISO 8601
  expiresAt:        string   // ISO 8601
  sponsorSignature: string   // base64url ML-DSA-65 sig by sponsor
}

export interface VerifyResult {
  valid:      boolean
  error?:     string
  agentKid?:  string
  sponsorKid?: string
  agentType?:  string
  label?:      string
  model?:      string
  scope?:      AgentScope
  issuedAt?:   string
  expiresAt?:  string
}

// ── AgentChainClient ──────────────────────────────────────────────────────────

export interface AgentRelayResult {
  txHash:      string
  blockNumber: number
}

export class AgentChainClient {
  constructor(opts: { relay: string; agent: KxcoAgentIdentity; timeout?: number })
  anchorAttestation(opts: { payloadHash: string; purpose: string }): Promise<AgentRelayResult>
  anchorAuditRoot(opts: { rootHash: string; entryCount: number }):   Promise<AgentRelayResult>
  transfer(opts: { to: string; amount: number }):                    Promise<AgentRelayResult>
}

// ── KxcoAgentIdentity ─────────────────────────────────────────────────────────

export interface Sponsor {
  kid:  string
  sign(message: Uint8Array): Promise<Uint8Array>
}

export interface CreateAgentOptions {
  sponsor:    Sponsor
  label:      string
  agentType:  'llm' | 'robot' | 'iot' | 'process'
  model?:     string
  scope:      AgentScope
  /** Mandatory. '7d', '30d', '1y', or seconds as number. */
  expiresIn:  string | number
  /** KxcoChain instance (from kxco-pq-chain) for on-chain registration. */
  chain?:     { issueAgentCredential(opts: object): Promise<AgentRelayResult> }
}

export interface ExportedAgentIdentity {
  'kxco-agent-identity': string
  kid:        string
  sponsorKid: string
  agentType:  string
  label:      string
  model?:     string
  scope:      AgentScope
  issuedAt:   string
  expiresAt:  string
  secretKey:  string
  publicKey:  string
  credential: AgentCredential
}

export class KxcoAgentIdentity {
  readonly kid:        string
  readonly sponsorKid: string
  readonly agentType:  string
  readonly label:      string
  readonly model:      string | null
  readonly scope:      AgentScope
  readonly issuedAt:   string
  readonly expiresAt:  string
  readonly credential: AgentCredential

  static create(opts: CreateAgentOptions): Promise<KxcoAgentIdentity>
  static import(exported: ExportedAgentIdentity): Promise<KxcoAgentIdentity>

  static verify(
    credential: AgentCredential,
    opts?: { sponsorPublicKey?: Uint8Array }
  ): Promise<VerifyResult>

  static revoke(
    agentKid: string,
    opts: { chain: { revokeAgentCredential(opts: object): Promise<AgentRelayResult> }; reason?: string }
  ): Promise<void>

  sign(message: Uint8Array): Promise<Uint8Array>
  getPublicKey(): Promise<Uint8Array>
  export(): ExportedAgentIdentity
  toChainClient(relay: string, opts?: { timeout?: number }): AgentChainClient
}
