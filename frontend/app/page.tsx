'use client'
import { useRouter } from 'next/navigation'
import { Shield, Mail, Search, ArrowRight, Cpu, Database, CheckCircle2, Radar } from 'lucide-react'

export default function Home() {
  const router = useRouter()

  const features = [
    { icon: <Mail size={18} color="#22d3ee" />, title: 'Moteur NLP', desc: 'DistilBERT fine-tuné sur 165K emails, TF-IDF en fallback' },
    { icon: <Database size={18} color="#818cf8" />, title: 'RAG threat intel', desc: '697 techniques MITRE ATT&CK, 183 groupes APT indexés' },
    { icon: <Search size={18} color="#f59e0b" />, title: 'Corrélation IOC', desc: 'VirusTotal, AbuseIPDB, URLHaus, OpenPhish en direct' },
    { icon: <Shield size={18} color="#22c55e" />, title: 'SIEM ready', desc: 'Règles Sigma générées automatiquement à chaque verdict' },
  ]

  const stats = [
    { label: 'Techniques MITRE', value: '697' },
    { label: 'Groupes APT', value: '183' },
    { label: 'IOCs actifs', value: '77K+' },
    { label: 'Modèle NLP', value: 'DistilBERT' },
  ]

  const pipeline = [
    { step: '01', title: 'Dépôt du .eml', desc: 'Headers, corps, pièces jointes', icon: <Mail size={16} color="#22d3ee" /> },
    { step: '02', title: 'Analyse multi-modules', desc: 'NLP + OCR + URLs + macros', icon: <Cpu size={16} color="#818cf8" /> },
    { step: '03', title: 'Corrélation RAG', desc: 'MITRE ATT&CK + threat intel', icon: <Radar size={16} color="#f59e0b" /> },
    { step: '04', title: 'Verdict + Sigma', desc: 'Score, explication, règle SIEM', icon: <CheckCircle2 size={16} color="#22c55e" /> },
  ]

  return (
    <div style={{ minHeight: '100vh', background: '#060a12', color: '#e2e8f0', fontFamily: 'Inter, system-ui, sans-serif', position: 'relative', overflow: 'hidden' }}>

      {/* Ambient grid background */}
      <div style={{
        position: 'absolute', inset: 0, opacity: 0.35, pointerEvents: 'none',
        backgroundImage: 'linear-gradient(#1e293b 1px, transparent 1px), linear-gradient(90deg, #1e293b 1px, transparent 1px)',
        backgroundSize: '48px 48px',
        maskImage: 'radial-gradient(ellipse 80% 60% at 50% 0%, black 20%, transparent 75%)',
        WebkitMaskImage: 'radial-gradient(ellipse 80% 60% at 50% 0%, black 20%, transparent 75%)',
      }} />

      {/* Header */}
      <header style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '22px 40px', borderBottom: '1px solid #1e293b' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <div style={{ width: 28, height: 28, borderRadius: 8, background: 'linear-gradient(135deg, #22d3ee, #6366f1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={15} color="#060a12" strokeWidth={2.5} />
          </div>
          <span style={{ fontSize: 15, fontWeight: 700, letterSpacing: '-0.01em' }}>MailShield</span>
        </div>
        <button onClick={() => router.push('/dashboard')} style={{ padding: '9px 20px', borderRadius: 7, border: '1px solid #22d3ee50', background: '#22d3ee0d', color: '#22d3ee', fontSize: 12, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit' }}>
          Ouvrir le dashboard
        </button>
      </header>

      {/* Hero */}
      <main style={{ position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', padding: '72px 20px 0' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 7, padding: '5px 13px', borderRadius: 20, background: '#22c55e12', border: '1px solid #22c55e30', fontSize: 11, color: '#22c55e', marginBottom: 28, fontFamily: 'JetBrains Mono, monospace' }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e' }} />
          moteur de détection actif
        </div>

        <h1 style={{ fontSize: 48, fontWeight: 800, maxWidth: 760, lineHeight: 1.15, margin: 0, letterSpacing: '-0.025em' }}>
          Un email peut mentir sur<br />
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, background: 'linear-gradient(90deg, #22d3ee, #818cf8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            qui l'a envoyé
          </span>. Pas sur ce qu'il contient.
        </h1>
        <p style={{ fontSize: 15, color: '#94a3b8', maxWidth: 540, marginTop: 20, lineHeight: 1.65 }}>
          MailShield analyse l'en-tête, le corps et les pièces jointes de chaque email, croise le résultat avec MITRE ATT&CK et les flux de menaces actifs, puis explique son verdict — en clair.
        </p>

        <button onClick={() => router.push('/dashboard')} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '14px 28px', borderRadius: 8, border: 'none', background: '#22d3ee', color: '#060a12', fontSize: 14, fontWeight: 700, cursor: 'pointer', marginTop: 32, fontFamily: 'inherit' }}>
          Scanner un email <ArrowRight size={16} />
        </button>

        {/* ── Signature: scanning email mockup ── */}
        <div style={{ position: 'relative', width: '100%', maxWidth: 620, marginTop: 64, marginBottom: 8 }}>
          <div style={{ position: 'relative', background: '#0d1424', border: '1px solid #1e293b', borderRadius: 12, overflow: 'hidden', textAlign: 'left', boxShadow: '0 30px 80px -20px #00000080' }}>

            {/* fake window bar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '10px 14px', borderBottom: '1px solid #1e293b', background: '#0a1120' }}>
              {['#ef4444', '#f59e0b', '#22c55e'].map(c => <div key={c} style={{ width: 8, height: 8, borderRadius: '50%', background: c, opacity: 0.6 }} />)}
              <span style={{ marginLeft: 8, fontSize: 10, color: '#334155', fontFamily: 'JetBrains Mono, monospace' }}>inbox — invoice_urgent.eml</span>
            </div>

            <div style={{ padding: '18px 20px', fontFamily: 'JetBrains Mono, monospace', fontSize: 12, lineHeight: 2.1, position: 'relative' }}>
              <div style={{ display: 'flex', gap: 8 }}>
                <span style={{ color: '#334155', width: 46, flexShrink: 0 }}>De:</span>
                <span style={{ color: '#e2e8f0' }}>billing@paypaI-secure.com</span>
                <span className="scan-tag scan-tag-1" style={{ fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 3, background: '#ef444422', color: '#ef4444', border: '1px solid #ef444450' }}>DOMAINE USURPÉ</span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <span style={{ color: '#334155', width: 46, flexShrink: 0 }}>Objet:</span>
                <span style={{ color: '#e2e8f0' }}>Action requise sous 24h — compte suspendu</span>
                <span className="scan-tag scan-tag-2" style={{ fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 3, background: '#f59e0b22', color: '#f59e0b', border: '1px solid #f59e0b50' }}>URGENCE ARTIFICIELLE</span>
              </div>
              <div style={{ color: '#64748b', marginTop: 6 }}>Bonjour,</div>
              <div style={{ color: '#64748b' }}>Nous avons détecté une activité inhabituelle. Cliquez ici pour vérifier :</div>
              <div style={{ display: 'flex', gap: 8, marginTop: 2 }}>
                <span style={{ color: '#22d3ee', textDecoration: 'underline' }}>hxxp://paypal-verify-account.tk/login</span>
                <span className="scan-tag scan-tag-3" style={{ fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 3, background: '#ef444422', color: '#ef4444', border: '1px solid #ef444450' }}>LIEN MALVEILLANT</span>
              </div>

              {/* scanning beam */}
              <div className="scan-beam" style={{ position: 'absolute', left: 0, right: 0, height: 2, background: 'linear-gradient(90deg, transparent, #22d3ee, transparent)', boxShadow: '0 0 12px 2px #22d3ee' }} />
            </div>

            {/* verdict footer */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 20px', borderTop: '1px solid #1e293b', background: '#0a1120' }}>
              <span style={{ fontSize: 9, fontWeight: 700, padding: '3px 8px', borderRadius: 4, background: '#ef444420', color: '#ef4444', border: '1px solid #ef444440' }}>PHISHING</span>
              <span style={{ fontSize: 11, color: '#475569', fontFamily: 'JetBrains Mono, monospace' }}>score 0.94 · T1566.002 · campagne PayPal-Spoofing</span>
            </div>
          </div>
        </div>

        {/* Stats ticker */}
        <div style={{ display: 'flex', gap: 44, marginTop: 68, flexWrap: 'wrap' as const, justifyContent: 'center' }}>
          {stats.map(s => (
            <div key={s.label}>
              <div style={{ fontSize: 25, fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', color: '#e2e8f0' }}>{s.value}</div>
              <div style={{ fontSize: 10.5, color: '#475569', marginTop: 3, letterSpacing: '0.02em' }}>{s.label}</div>
            </div>
          ))}
        </div>
      </main>

      {/* Features */}
      <section style={{ position: 'relative', padding: '90px 20px 20px', maxWidth: 980, margin: '0 auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 16 }}>
          {features.map(f => (
            <div key={f.title} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 20, textAlign: 'left', transition: 'border-color 0.2s' }}>
              <div style={{ marginBottom: 12 }}>{f.icon}</div>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>{f.title}</div>
              <div style={{ fontSize: 11.5, color: '#64748b', lineHeight: 1.55 }}>{f.desc}</div>
            </div>
          ))}
        </div>

        {/* Pipeline — real sequence, numbering justified */}
        <div style={{ marginTop: 24, background: '#0d1424', border: '1px solid #1e293b', borderRadius: 12, padding: '28px 32px' }}>
          <div style={{ fontSize: 11, color: '#22d3ee', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase' as const, marginBottom: 20, fontFamily: 'JetBrains Mono, monospace' }}>
            Le pipeline, de bout en bout
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 20 }}>
            {pipeline.map((s, i) => (
              <div key={s.step} style={{ display: 'flex', flexDirection: 'column', gap: 8, position: 'relative' }}>
                <div style={{ fontSize: 10.5, color: '#334155', fontFamily: 'JetBrains Mono, monospace' }}>{s.step}</div>
                {s.icon}
                <div style={{ fontSize: 12.5, fontWeight: 600, color: '#e2e8f0' }}>{s.title}</div>
                <div style={{ fontSize: 11, color: '#64748b' }}>{s.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer style={{ position: 'relative', borderTop: '1px solid #1e293b', padding: '22px 40px', textAlign: 'center', fontSize: 11, color: '#334155', marginTop: 60 }}>
        MailShield — projet réalisé dans le cadre d'un stage cybersécurité chez DASEC Group
      </footer>

      <style>{`
        @keyframes scanY {
          0%   { top: 4%; opacity: 0; }
          8%   { opacity: 1; }
          48%  { opacity: 1; }
          55%  { top: 92%; opacity: 0; }
          100% { top: 92%; opacity: 0; }
        }
        .scan-beam { animation: scanY 4s ease-in-out infinite; }

        @keyframes tagReveal { from { opacity: 0; transform: translateY(-2px); } to { opacity: 1; transform: translateY(0); } }
        .scan-tag { opacity: 0; animation: tagReveal 0.4s ease forwards; }
        .scan-tag-1 { animation-delay: 0.35s; }
        .scan-tag-2 { animation-delay: 1.55s; }
        .scan-tag-3 { animation-delay: 2.35s; }

        @media (prefers-reduced-motion: reduce) {
          .scan-beam { animation: none; opacity: 0; }
          .scan-tag { animation: none; opacity: 1; }
        }
      `}</style>
    </div>
  )
}