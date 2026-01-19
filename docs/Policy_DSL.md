## SluiceGate Policy DSL (Beta)

This section defines the **Beta-stable Policy DSL** for the SluiceGate Open Core.

The Policy DSL is intentionally **general-purpose**. It is designed to govern **any actor, any action, any target, and any context**, not just monetary or transactional use cases.

### Design Principles
- Policies are declarative, not imperative
- Policy evaluation is deterministic
- Rules are evaluated top-to-bottom
- First matching rule wins
- Conditions within a rule are AND-only in Beta
- Policy decisions may include obligations
- Policy provenance is cryptographically anchored via a hash

### Decisions
Every policy evaluation returns one of:
- ALLOW — proceed immediately
- PAUSE — require explicit approval before proceeding
- BLOCK — do not proceed

### Request Model
Policies evaluate a request composed of four top-level objects:
- actor — who or what is requesting the action
- action — what is being requested
- target — what the action applies to
- context — environmental, risk, or metadata signals

Conceptual request structure:
<pre lang="yaml">actor:
  type: "agent"
  id: "agent-123"
  role: "automation"

action:
  name: "data.write"
  params:
    rows: 1000

target:
  type: "database"
  id: "prod-main"

context:
  env: "prod"
  risk_score: 75
  sensitivity: "PII"</pre>

### Policy File Structure
A policy file is a YAML document containing:
- an optional version
- a required default decision
- an ordered list of rules

Example policy:
<pre lang="yaml">version: 1

default:
  decision: PAUSE
  obligations:
    - type: require_approval
      approver_group: Security
      reason: "Default safe posture"

rules:
  - name: "Pause high-risk writes to production"
    when:
      - path: "action.name"
        eq: "data.write"
      - path: "context.env"
        eq: "prod"
      - path: "context.risk_score"
        gte: 70
    decision: PAUSE
    obligations:
      - type: require_approval
        approver_group: Security
        reason: "High-risk write to prod"

  - name: "Block sensitive data exfiltration"
    when:
      - path: "action.name"
        eq: "data.export"
      - path: "context.sensitivity"
        in: ["PII", "PHI", "CONFIDENTIAL"]
    decision: BLOCK</pre>

### Rule Evaluation Semantics
- Rules are evaluated in order
- Each rule contains a when clause: a list of conditions
- All conditions must match (AND-only in Beta)
- The first matching rule determines the decision
- If no rule matches, the default decision applies

### Conditions (Beta)
Each condition includes:
- a path (dot-notation reference into the request)
- exactly one operator

Supported operators:

Equality
<pre lang="yaml">- path: "action.name"
  eq: "data.read"</pre>

Membership
<pre lang="yaml">- path: "context.sensitivity"
  in: ["PII", "PHI"]</pre>

Existence
<pre lang="yaml">- path: "actor.role"
  exists: true</pre>

Numeric comparison
<pre lang="yaml">- path: "context.risk_score"
  gt: 50</pre>

Numeric operators supported in Beta: gt, gte, lt, lte

### Path Resolution
Paths use dot notation to traverse the request object.
Examples: actor.type, action.name, action.params.amount, target.id, context.env

If a path does not exist:
- exists: false evaluates to true
- all other operators evaluate to false

### Obligations (Beta)
Obligations are structured metadata attached to a policy decision.
They describe required handling steps that must be satisfied before or after execution.
Obligations are not executed by the core; they are enforced by adapters (approval workflows, UIs, connectors).

Example obligation:
<pre lang="yaml">obligations:
  - type: require_approval
    approver_group: Finance
    reason: "High-risk operation"</pre>

Supported obligation types in Beta:
- require_approval (approver_group required; reason optional)

Unknown obligation types should be ignored by adapters that do not recognize them.

### Policy Provenance
Policy provenance is defined as the SHA-256 hash of the policy file contents:
<pre lang="text">policy_hash = sha256(policy_file_bytes)</pre>

Every decision must report the policy_hash that produced it.
Audit logs may display an abbreviated form (first eight hex characters followed by “..”) for readability.

### Beta Constraints (Intentional)
- Conditions are AND-only (no OR / grouping)
- No computed expressions
- No regex matching
- No side effects inside policy evaluation
- No implicit execution based on obligations

### Summary
The SluiceGate Policy DSL provides a deterministic, auditable, and extensible framework for governing agent-initiated actions across arbitrary domains. It is designed to scale from simple demos to enterprise-grade control planes without changing its fundamental model.
