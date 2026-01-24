# SluiceGate Policy DSL (Beta)

This section defines the **Beta-stable Policy DSL** for the SluiceGate Open Core.

The Policy Domain Specific Language (DSL) is intentionally **general-purpose**. It is designed to govern **any actor, any action, any target, and any context**, not just monetary or transactional use cases.

---

## Design Principles

- Policies are declarative, not imperative
- Policy evaluation is deterministic
- Rules are evaluated top-to-bottom (**first matching rule wins**)
- Conditions within a rule are **AND-only** in Beta (may expand to OR/grouping later)
- Policy decisions may include obligations
- Policy provenance is cryptographically anchored via a hash

---

## Decisions

Every policy evaluation returns one of:

- **ALLOW** — proceed immediately
- **PAUSE** — require explicit (human) approval before proceeding
- **BLOCK** — do not proceed

---

## Request Model

Policies evaluate a request composed of four top-level objects:

- **actor** — who or what is requesting the action
- **action** — what is being requested
- **target** — what the action applies to
- **context** — environmental/risk/session/temporal metadata; “under what conditions is this action being proposed?”

Conceptual request structure:

```yaml
actor:
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
  sensitivity: "PII"
```

> **Important:** Policy paths must match the request shape you provide to the core. For example, if you put `amount` under `context.amount`, your policy should reference `context.amount` (not `action.params.amount`).

---

## Policy File Structure

A policy file is a YAML document containing:

- an optional `version`
- a required `default` block
- an ordered list of `rules`

### Canonical structure

```yaml
version: 1

default:
  decision: PAUSE
  obligations: []   # optional

rules:
  - name: "Example rule name"
    when:
      - path: "action.name"
        eq: "data.write"
    decision: PAUSE
    obligations: [] # optional
```

### Notes on DSL shape (the format we support)

Each condition is a YAML object with:

- `path` (required)
- **exactly one operator key** (required), such as `eq`, `lte`, `in`, etc.

✅ Supported:

```yaml
- path: "context.env"
  eq: "prod"
```

❌ Not supported (deprecated / not implemented):

```yaml
- path: "context.env"
  operator: eq
  expected: prod
```

---

## Example: Stripe refund thresholds

```yaml
version: 1

default:
  decision: PAUSE

rules:
  - name: "Allow small refunds"
    when:
      - path: "action.name"
        eq: "stripe.refund"
      - path: "context.amount"
        lte: 100
      - path: "context.currency"
        eq: "USD"
    decision: ALLOW

  - name: "Pause medium refunds"
    when:
      - path: "action.name"
        eq: "stripe.refund"
      - path: "context.amount"
        lte: 500
      - path: "context.currency"
        eq: "USD"
    decision: PAUSE

  - name: "Block large refunds"
    when:
      - path: "action.name"
        eq: "stripe.refund"
      - path: "context.amount"
        gt: 500
      - path: "context.currency"
        eq: "USD"
    decision: BLOCK
```

---

## Rule Evaluation Semantics

- Rules are evaluated in order
- Each rule contains a `when` clause (a list of conditions)
- **All** conditions must match (AND-only)
- The first matching rule determines the `decision`
- If no rule matches, the `default.decision` applies

---

## Conditions (Beta)

Each condition includes:

- a `path` (dot-notation reference into the request)
- exactly one operator key

### Supported operators

**Equality**
```yaml
- path: "action.name"
  eq: "data.read"
```

**Membership**
```yaml
- path: "context.sensitivity"
  in: ["PII", "PHI"]
```

**Existence**
```yaml
- path: "actor.role"
  exists: true
```

**Numeric comparisons**
```yaml
- path: "context.risk_score"
  gt: 50
```

Numeric operators supported in Beta: `gt`, `gte`, `lt`, `lte`

### Type behavior

- `eq` compares values directly (case-sensitive for strings).
- Numeric operators expect numeric values. Use YAML numbers (`100`, `500`), not quoted strings (`"100"`).

---

## Path Resolution

Paths use dot notation to traverse the request object.

Examples:

- `actor.type`
- `action.name`
- `action.params.amount`
- `target.id`
- `context.env`

If a path does not exist:

- `exists: false` evaluates to **true**
- all other operators evaluate to **false**

---

## Obligations (Beta)

Obligations are structured metadata attached to a policy decision. They describe required handling steps that must be satisfied before or after execution.

**Important:** Obligations are not “executed” by the core. They are enforced by adapters (approval workflows, UIs, connectors).

Example obligation:

```yaml
obligations:
  - type: require_approval
    approver_group: Finance
    reason: "High-risk operation"
```

Supported obligation types in Beta:

- `require_approval` (requires `approver_group`; `reason` optional)

Unknown obligation types should be ignored by adapters that do not recognize them.

---

## Policy Provenance

Policy provenance is defined as the SHA-256 hash of the policy file contents:

```text
policy_hash = sha256(policy_file_bytes)
```

Every decision must report the `policy_hash` that produced it. Audit logs may display an abbreviated form (first eight hex characters followed by “..”) for readability.

---

## Beta Constraints (Intentional)

- Conditions are AND-only (no OR / grouping)
- No computed expressions
- No regex matching
- No side effects inside policy evaluation
- No implicit execution based on obligations

---

## Summary

The SluiceGate Policy DSL provides a deterministic, auditable, and extensible framework for governing agent-initiated actions across arbitrary domains. It is designed to scale from simple demos to enterprise-grade control planes without changing its fundamental model.
