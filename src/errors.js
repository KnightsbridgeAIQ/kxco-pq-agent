export class KxcoPqAgentError extends Error {
  constructor(message, { code } = {}) {
    super(message)
    this.name = 'KxcoPqAgentError'
    this.code = code ?? 'AGENT_ERROR'
  }
}
