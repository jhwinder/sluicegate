import React, { useState, useEffect } from "react"
import YAML from "js-yaml"

const defaultPolicy = {
  version: 1,
  default: { decision: "PAUSE" },
  rules: [],
}

function emptyCondition() {
  return { path: "", operator: "eq", value: "" }
}

function emptyRule() {
  return { name: "", when: [emptyCondition()], decision: "PAUSE", obligations: [] }
}

export default function PolicyForm({ initialPolicy }) {
  const [policy, setPolicy] = useState(initialPolicy || defaultPolicy)
  const [yamlPreview, setYamlPreview] = useState("")
  const [messages, setMessages] = useState(null)

  // Normalize incoming policy dict (operator as key) into form-friendly shape
  function normalizePolicy(p) {
    if (!p) return defaultPolicy
    const operators = ["exists", "eq", "in", "gt", "gte", "lt", "lte"]
    const copy = JSON.parse(JSON.stringify(p))
    copy.rules = (copy.rules || []).map(r => {
      const when = (r.when || []).map(cond => {
        const path = cond.path || ""
        let op = "exists"
        let val = cond["exists"]
        for (const k of Object.keys(cond)) {
          if (k === 'path') continue
          if (operators.includes(k)) {
            op = k
            val = cond[k]
            break
          }
        }
        // convert list to comma-separated string for editing
        if (op === 'in' && Array.isArray(val)) val = val.join(', ')
        return { path, operator: op, value: val }
      })
      return { ...r, when }
    })
    return copy
  }

  // Denormalize form policy back into expected policy dict with operator keys
  function denormalizePolicy(p) {
    const copy = JSON.parse(JSON.stringify(p || {}))
    copy.rules = (copy.rules || []).map(r => {
      const when = (r.when || []).map(cond => {
        const path = cond.path || ''
        const op = cond.operator || 'exists'
        let val = cond.value
        if (op === 'in') {
          if (typeof val === 'string') {
            val = val.split(',').map(s => s.trim()).filter(Boolean)
          }
        }
        if (op === 'exists') {
          // coerce truthy strings to booleans
          if (typeof val === 'string') {
            const lc = val.toLowerCase()
            val = lc === 'true' || lc === '1'
          } else {
            val = Boolean(val)
          }
        }
        // numeric conversion for comparison ops
        if (['gt','gte','lt','lte'].includes(op)) {
          if (typeof val === 'string' && val !== '') {
            const n = Number(val)
            if (!Number.isNaN(n)) val = n
          }
        }
        return { path, [op]: val }
      })
      const out = { ...r }
      out.when = when
      return out
    })
    return copy
  }

  useEffect(() => {
    setPolicy(normalizePolicy(initialPolicy))
  }, [initialPolicy])

  useEffect(() => {
    try {
      setYamlPreview(YAML.dump(denormalizePolicy(policy)))
    } catch (e) {
      setYamlPreview("")
    }
  }, [policy])

  function updatePolicy(path, value) {
    setPolicy(prev => {
      const next = JSON.parse(JSON.stringify(prev))
      const parts = path.split('.')
      let cur = next
      for (let i = 0; i < parts.length - 1; i++) cur = cur[parts[i]]
      cur[parts[parts.length - 1]] = value
      return next
    })
  }

  function addRule() {
    setPolicy(p => ({ ...p, rules: [...(p.rules || []), emptyRule()] }))
  }

  function removeRule(idx) {
    setPolicy(p => {
      const rules = [...(p.rules || [])]
      rules.splice(idx, 1)
      return { ...p, rules }
    })
  }

  function updateRule(idx, field, value) {
    setPolicy(p => {
      const rules = JSON.parse(JSON.stringify(p.rules || []))
      rules[idx][field] = value
      return { ...p, rules }
    })
  }

  function addCondition(ruleIdx) {
    setPolicy(p => {
      const rules = JSON.parse(JSON.stringify(p.rules || []))
      rules[ruleIdx].when.push(emptyCondition())
      return { ...p, rules }
    })
  }

  function updateCondition(ruleIdx, condIdx, field, value) {
    setPolicy(p => {
      const rules = JSON.parse(JSON.stringify(p.rules || []))
      rules[ruleIdx].when[condIdx][field] = value
      return { ...p, rules }
    })
  }

  function removeCondition(ruleIdx, condIdx) {
    setPolicy(p => {
      const rules = JSON.parse(JSON.stringify(p.rules || []))
      rules[ruleIdx].when.splice(condIdx, 1)
      return { ...p, rules }
    })
  }

  async function validate() {
    setMessages(null)
    const payload = denormalizePolicy(policy)
    const resp = await fetch('/api/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
    const data = await resp.json()
    setMessages(data)
    return data
  }

  async function save() {
    setMessages(null)
    const payload = denormalizePolicy(policy)
    const resp = await fetch('/api/policy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
    const data = await resp.json()
    if (!resp.ok) setMessages(data)
    else setMessages(data)
  }

  async function upload(e) {
    const file = e.target.files[0]
    if (!file) return
    const fd = new FormData()
    fd.append('file', file)
    const resp = await fetch('/api/upload', { method: 'POST', body: fd })
    const data = await resp.json()
    setMessages(data)
    if (resp.ok) window.location.reload()
  }

  return (
    <div>
      <div style={{ marginBottom: 12 }}>
        <label>Version: </label>
        <input type="number" value={policy.version || ''} onChange={e => updatePolicy('version', parseInt(e.target.value || '0'))} />
        <label style={{ marginLeft: 12 }}>Default decision: </label>
        <select value={policy.default?.decision || 'PAUSE'} onChange={e => updatePolicy('default', { ...policy.default, decision: e.target.value })}>
          <option>ALLOW</option>
          <option>PAUSE</option>
          <option>BLOCK</option>
        </select>
      </div>

      <div>
        <h3>Rules</h3>
        {(policy.rules || []).map((r, idx) => (
          <div key={idx} style={{ border: '1px solid #ddd', padding: 8, marginBottom: 8 }}>
            <div>
              <label>Name: </label>
              <input value={r.name} onChange={e => updateRule(idx, 'name', e.target.value)} />
              <label style={{ marginLeft: 8 }}>Decision: </label>
              <select value={r.decision || 'PAUSE'} onChange={e => updateRule(idx, 'decision', e.target.value)}>
                <option>ALLOW</option>
                <option>PAUSE</option>
                <option>BLOCK</option>
              </select>
              <button style={{ marginLeft: 8 }} onClick={() => removeRule(idx)}>Remove rule</button>
            </div>
            <div style={{ marginTop: 8 }}>
              <strong>When</strong>
              {(r.when || []).map((c, ci) => (
                <div key={ci} style={{ marginTop: 4 }}>
                  <input placeholder="path" value={c.path} onChange={e => updateCondition(idx, ci, 'path', e.target.value)} />
                  <select value={c.operator} onChange={e => updateCondition(idx, ci, 'operator', e.target.value)} style={{ marginLeft: 4 }}>
                    <option value="exists">exists</option>
                    <option value="eq">eq</option>
                    <option value="in">in</option>
                    <option value="gt">gt</option>
                    <option value="gte">gte</option>
                    <option value="lt">lt</option>
                    <option value="lte">lte</option>
                  </select>
                  <input placeholder="value" value={c.value} onChange={e => updateCondition(idx, ci, 'value', e.target.value)} style={{ marginLeft: 4 }} />
                  <button onClick={() => removeCondition(idx, ci)} style={{ marginLeft: 4 }}>Remove</button>
                </div>
              ))}
              <div style={{ marginTop: 6 }}>
                <button onClick={() => addCondition(idx)}>Add condition</button>
              </div>
            </div>
          </div>
        ))}
        <button onClick={addRule}>Add rule</button>
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={validate}>Validate</button>
        <button onClick={save} style={{ marginLeft: 8 }}>Save (lint & backup)</button>
        <label style={{ marginLeft: 12 }}>
          Upload YAML:
          <input type="file" accept=".yml,.yaml" onChange={upload} />
        </label>
      </div>

      {messages && (
        <pre style={{ background: '#f8f8f8', padding: 8, marginTop: 12 }}>{JSON.stringify(messages, null, 2)}</pre>
      )}

      <div style={{ marginTop: 12 }}>
        <h3>YAML Preview</h3>
        <pre style={{ background: '#fff', padding: 8, border: '1px solid #eee' }}>{yamlPreview}</pre>
      </div>
    </div>
  )
}
