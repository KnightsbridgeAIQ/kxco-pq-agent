# Changelog

## 1.1.1

checkScope denies an amount, spentToday or limit that is not a finite number,
and any section, limit or `enabled` switch of the wrong type, naming it.
validateScope requires positive integer limits, string recipients and boolean
`enabled` switches. verify() and import() validate the scope they return, and
verify() treats an expiresAt that is not a date as expired. A scope key named
`__proto__` is refused.

Credential text fields and relay intent header fields must be one line of
well-formed text, and AgentChainClient refuses a relay that is not a string.
The typings now say that an empty purposes list allows no purpose.

**The npm page leads with what the package proves.** The first screen now says
who answers for an agent, what it may do and how both ends enforce it, the
evidence underneath and the migration dates set by NIST, Executive Order 14412,
OMB M-26-15 and the UK NCSC.

A family table maps every KXCO package to the job it does, and a new For
institutions section sets out the operated services and how to reach us. The
evidence documents are unchanged and linked from the page.

The scope manifest example uses a complete recipient address, so it validates
as written, and the page gains Security, Release integrity and License sections.

A NOTICE file names the copyright owner, Knightsbridge Financial Ltd, trading
as KXCO, and ships in the package, so anyone who redistributes it carries the
attribution, as section 4(d) of the Apache License requires.

## 1.1.0

**`checkScope()` enforces the scope locally, before the relay sees the action.**

```js
import { checkScope } from 'kxco-pq-agent'

const decision = checkScope(agent.scope, {
  type: 'payment', amount: 4500, spentToday: 12000, recipient: '0xAbC…',
})
// { allowed: false,
//   reason: "amount 4500 would take today's total to 16500, past maxPerDay 15000",
//   checked: ['payments.enabled', 'payments.maxPerTransaction', 'payments.maxPerDay'] }
```

The relay's enforcement is unchanged and is still the one that binds, because it
sits behind the agent where a compromised agent cannot reach it. This runs in
front, on the same signed scope, and earns its place three ways: it refuses
offline, so an agent that cannot reach the relay still knows what it may not do;
it refuses without spending a round trip; and it names the limit that stopped
it, which a remote refusal cannot do as precisely.

**Fails closed throughout.** A capability the scope does not grant is denied. An
action type it does not recognise is denied. A configured limit that cannot be
judged from the inputs given is denied rather than skipped — pass a scope with
`maxPerDay` set and no `spentToday`, and the answer is a refusal that says which
input is missing, not a pass that quietly skipped a control.

`checked` reports every limit the decision actually evaluated, in the order
applied, so a caller can show the control ran rather than assert it did.

Covers payments (`maxPerTransaction`, `maxPerDay`, `allowedRecipients`, with EVM
recipients matched case-insensitively), attestation purposes, `auditLog` and
`credentials`. Eleven tests.

**ASSESSMENT.md rewritten** to lead with the containment properties — an agent
cannot widen its own authority, cannot mint another agent, and always traces to
a KYC-verified institution — and to record that enforcement now runs at both
ends.
