# SluiceGate Open Core — Quick Start

This guide walks you through running the **SluiceGate Open Core** and the included **demo application** in under 5 minutes.  
By the end, you will see:

- an AI-initiated action **allowed**
- a higher-risk action **paused for human approval**
- a very high-risk action **blocked**
- a paused action **resumed after approval**

---

## What is SluiceGate?

SluiceGate is a **policy-driven control plane for AI and autonomous agents**.

Instead of agents directly executing high-risk actions (API calls, transactions, system changes), actions are evaluated against a declarative policy that can:

- **ALLOW** — proceed immediately  
- **PAUSE** — wait for explicit human approval  
- **BLOCK** — deny execution  

The Open Core provides:
- a deterministic policy engine
- a first-class **PAUSE / resume token** primitive
- auditable decision traces

The demo application shows how these primitives are used in practice.

---

## Prerequisites

- Docker
- Docker Compose  
- (Optional) `uv` for local Python experimentation

No Python environment setup is required to run the demo.

---

## Repository Layout (high level)

```
.
├── open-core/          # SluiceGate core engine (policy + decision loop)
│   └── src/sg_core/
├── sluice-demo/        # Minimal web demo that calls sg-core
│   ├── backend/
│   ├── frontend/
│   └── policies/
└── docs/
```

Key point: **The demo does not duplicate the core engine.**  
It imports `sg-core` as a dependency, exactly as an external developer would.

---

## 1. Run the Demo (Recommended Path)

From the repository root:

```bash
cd sluice-demo
docker compose up --build
```

This starts:

- **Backend API** → http://localhost:8000  
- **Frontend UI** → http://localhost:8080  

Verify backend health:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{ "ok": true }
```

---

## 2. Try the Built-In Policy

Open the UI:  
http://localhost:8080

The demo simulates an AI agent attempting a Stripe refund.

Try the preset amounts:

| Amount | Result | Explanation |
|------|-------|------------|
| $100 | **ALLOW** | Low-risk refund executes immediately |
| $500 | **PAUSE** | Requires human approval |
| $1000 | **BLOCK** | Explicitly denied by policy |

You’ll see:
- the gate decision
- the policy hash
- an audit trail
- (for PAUSE) approval links

---

## 3. Human Approval Flow (PAUSE)

When a request is **PAUSE**:

1. The request is stored with a **resume token**
2. An approval email is sent with:
   - `/approve` link
   - `/reject` link
3. Clicking **Approve** resumes execution
4. Clicking **Reject** terminates the request

The demo UI updates automatically when the request resumes.

This demonstrates that PAUSE is **not an error** — it is a durable waiting state.

---

## 4. “Agent Waits, Then Resumes” Behavior

The demo includes a **Run Agent (auto-wait)** mode that simulates correct agent behavior:

1. Agent submits an action
2. If decision is **PAUSE**, the agent waits
3. Agent polls for status
4. Once approved or rejected, the agent resumes or exits cleanly

This highlights a key difference vs. traditional API gateways:
the agent does not retry alternative APIs or lose context.

---

## 5. Editing the Policy

The active policy file is:

```
sluice-demo/policies/policy.yml
```

Example:

```yaml
version: 1

default:
  decision: PAUSE

rules:
  - name: Allow small refunds
    when:
      - path: action.name
        eq: stripe.refund
      - path: context.amount
        lte: 100
      - path: context.currency
        eq: USD
    decision: ALLOW

  - name: Block large refunds
    when:
      - path: action.name
        eq: stripe.refund
      - path: context.amount
        gt: 500
      - path: context.currency
        eq: USD
    decision: BLOCK
```

After editing the policy, either:

Restart Docker:
```bash
docker compose restart backend
```

OR reload in place:
```bash
curl -X POST http://localhost:8000/api/policy/reload
```

---

## 6. Using sg-core Without the Demo

To experiment with the core engine directly:

```bash
cd open-core
uv sync
uv run python examples/run_local_decision.py
```

---

## Policy DSL Notes

- Conditions use **operator keys** (`eq`, `gt`, `lte`, etc.)
- Conditions are **AND-only**
- Rules are evaluated top-to-bottom (first match wins)

Full DSL reference:
`docs/Policy_DSL.md`

---

## What This Demo Is (and Is Not)

**This demo is:**
- a minimal, auditable AI control loop
- a reference architecture for PAUSE / resume
- intentionally simple and inspectable

**This demo is not:**
- a workflow engine
- an API gateway
- a full orchestration system

Those layers belong above SluiceGate, not inside it.

---

## Summary

SluiceGate provides a clean, deterministic way to:

- control AI actions
- require human approval where appropriate
- resume safely and audibly
- keep agents aligned with organizational intent

If an agent can act — it can be gated.