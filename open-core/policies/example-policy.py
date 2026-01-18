version: 1

default:
  decision: PAUSE
  obligations:
    - type: require_approval
      approver_group: Security
      reason: "Default safe posture"

rules:
  - name: "Allow low-risk read access in dev"
    when:
      - path: "action.name"
        eq: "data.read"
      - path: "context.env"
        eq: "dev"
      - path: "context.risk_score"
        lte: 30
    decision: ALLOW
    obligations: []

  - name: "Pause high-risk writes to prod"
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

  - name: "Block exfil attempts"
    when:
      - path: "action.name"
        eq: "data.export"
      - path: "context.sensitivity"
        in: ["PHI", "PII", "CONFIDENTIAL"]
    decision: BLOCK
    obligations: []
