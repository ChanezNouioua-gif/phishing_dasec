'use client'
import { useRouter } from 'next/navigation'
import { Shield, Mail, Search, ArrowRight } from 'lucide-react'

export default function Home() {
  const router = useRouter()
  return (
    <div style={{ minHeight: '100vh', background: '#0a0f1a', color: '#e2e8f0', fontFamily: 'Inter, system-ui, sans-serif', display: 'flex', flexDirection: 'column' }}>
      <header style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '20px 40px' }}>
        <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Shield size={15} color="#fff" />
        </div>
        <span style={{ fontSize: 15, fontWeight: 700 }}>MailShield</span>
      </header>

      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', padding: '0 20px' }}>
        <h1 style={{ fontSize: 42, fontWeight: 800, maxWidth: 700, lineHeight: 1.2, margin: 0 }}>
          Détection de phishing par IA pour votre SOC
        </h1>
        <p style={{ fontSize: 16, color: '#94a3b8', maxWidth: 560, marginTop: 16 }}>
          Analyse NLP, threat intelligence MITRE ATT&CK, et intégration SIEM en temps réel — protégez votre organisation contre les menaces par email.
        </p>
        <button onClick={() => router.push('/login')} style={{ marginTop: 32, display: 'flex', alignItems: 'center', gap: 8, padding: '12px 24px', borderRadius: 8, border: 'none', background: '#2563eb', color: '#fff', fontSize: 14, fontWeight: 600, cursor: 'pointer' }}>
          Accéder à la plateforme <ArrowRight size={16} />
        </button>

        <div style={{ display: 'flex', gap: 32, marginTop: 64 }}>
          {[
            { icon: <Mail size={20} color="#3b82f6" />, label: 'Analyse d\'emails', desc: 'DistilBERT + NLP' },
            { icon: <Search size={20} color="#8b5cf6" />, label: 'Threat Intel', desc: 'MITRE ATT&CK + IOCs' },
            { icon: <Shield size={20} color="#22c55e" />, label: 'SIEM ready', desc: 'Sigma rules auto' },
          ].map(f => (
            <div key={f.label} style={{ textAlign: 'left' }}>
              {f.icon}
              <div style={{ fontSize: 13, fontWeight: 600, marginTop: 8 }}>{f.label}</div>
              <div style={{ fontSize: 11, color: '#64748b' }}>{f.desc}</div>
            </div>
          ))}
        </div>
      </main>
    </div>
  )
}