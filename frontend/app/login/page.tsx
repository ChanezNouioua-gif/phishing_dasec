'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Shield, Lock } from 'lucide-react'

export default function LoginPage() {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const router = useRouter()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true); setError('')
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    })
    if (res.ok) {
      router.push('/dashboard')
    } else {
      setError('Mot de passe incorrect')
    }
    setLoading(false)
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0a0f1a', fontFamily: 'Inter, system-ui, sans-serif' }}>
      <form onSubmit={handleLogin} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 32, width: 340, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={18} color="#fff" />
          </div>
          <span style={{ fontSize: 16, fontWeight: 700, color: '#f1f5f9' }}>MailShield</span>
        </div>
        <p style={{ fontSize: 12, color: '#64748b', margin: 0 }}>Connectez-vous pour accéder à la plateforme</p>
        <div style={{ position: 'relative' }}>
          <Lock size={14} color="#475569" style={{ position: 'absolute', left: 12, top: 12 }} />
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="Mot de passe"
            style={{ width: '100%', padding: '10px 12px 10px 34px', borderRadius: 6, border: '1px solid #1e293b', background: '#0a1120', color: '#e2e8f0', fontSize: 13, outline: 'none' }}
          />
        </div>
        {error && <div style={{ fontSize: 11, color: '#ef4444' }}>{error}</div>}
        <button type="submit" disabled={loading} style={{ padding: 10, borderRadius: 6, border: 'none', background: '#2563eb', color: '#fff', fontWeight: 600, fontSize: 13, cursor: 'pointer' }}>
          {loading ? 'Connexion...' : 'Se connecter'}
        </button>
      </form>
    </div>
  )
}