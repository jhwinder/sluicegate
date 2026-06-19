import React, { useEffect, useState } from "react"
import PolicyForm from "./PolicyForm"

export default function App() {
  const [policy, setPolicy] = useState(null)

  useEffect(() => {
    fetch('/api/policy')
      .then(r => {
        if (!r.ok) return null
        return r.json()
      })
      .then(data => {
        if (data && data.policy) setPolicy(data.policy)
      })
      .catch(() => {})
  }, [])

  return (
    <div style={{ padding: 20, fontFamily: 'Arial, sans-serif' }}>
      <h2>SluiceGate Policy Editor</h2>
      <PolicyForm initialPolicy={policy} />
    </div>
  )
}
