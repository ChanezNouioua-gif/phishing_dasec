'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Shield, AlertTriangle, Mail, FileText, Plug, RefreshCw,
  Settings, Activity, Download, Circle, File, Link, Eye, 
  Binary, Terminal, Cpu, Layers
} from 'lucide-react'

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

// ── Types ──────────────────────────────────────────────────────
interface HealthData {
  status: string
  rag_collections: Record<string, number>
  ioc_feeds: { urlhaus: number; openphish: number }
  llm_backend: string
  threat_intel_apis: { virustotal: boolean; abuseipdb: boolean }
  soc_alert: boolean
}

interface Analysis {
  analysis_id: string
  analyzed_at: string
  mode: string
  score_global: number
  verdict: string
  sender: string
  subject: string
  technique_attck: string
  campaign: string
  sigma_count: number
  alert_sent: boolean
}

interface StatsData {
  total_analyses: number
  by_verdict: Record<string, number>
  avg_score: number
  total_iocs: number
  top_techniques: Array<{ technique: string; count: number }>
  top_campaigns: Array<{ campaign: string; count: number }>
}

interface AnalyzeResult {
  analysis_id: string
  score_global: number
  verdict: string
  // Champs additionnels potentiels du backend pour les métadonnées de l'email
  email_meta?: {
    from?: string
    to?: string
    reply_to?: string
    return_path?: string
    spf?: string
    dkim?: string
    dmarc?: string
    subject?: string
  }
  // Pièces jointes et outils spécifiques avancés
  attachments?: Array<{
    filename: string
    size: number
    mime_type: string
    oletools_macro_detected?: boolean
    oletools_findings?: string[]
  }>
  ocr_results?: Array<{
    image_name: string
    extracted_text: string
  }>
  pdf_content_extracted?: string[]
  report: {
    confiance: string
    campagne_probable: string
    technique_attck: string
    vecteur_attaque: string
    indicateurs_cles: string[]
    explication: string
    recommandation: string
    iocs: {
      urls_suspectes: string[]
      ips_malveillantes: string[]
      hashes: string[]
    }
  }
  sigma_rules: {
    rules_count: number
    combined_yaml: string
  }
  threat_intel: {
    score: number
    iocs_detected: string[]
  }
  nlp: { bert_score: number; lr_score: number; score: number }
  urls: { score: number; suspicious: string[]; findings: string[] }
}

// ── Helpers ────────────────────────────────────────────────────
function scoreColor(score: number) {
  if (score >= 0.7) return 'var(--red)'
  if (score >= 0.4) return 'var(--amber)'
  return 'var(--green)'
}

function verdictColor(verdict: string) {
  if (verdict === 'PHISHING') return 'var(--red)'
  if (verdict === 'SUSPECT') return 'var(--amber)'
  return 'var(--green)'
}

function ScoreBar({ value, color }: { value: number; color: string }) {
  return (
    <div style={{ height: 2, background: 'var(--surface-3)', borderRadius: 1, overflow: 'hidden', marginTop: 4 }}>
      <div style={{ height: '100%', width: `${Math.round(value * 100)}%`, background: color, borderRadius: 1 }} />
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────
export default function Dashboard() {
  const [health, setHealth] = useState<HealthData | null>(null)
  const [stats, setStats] = useState<StatsData | null>(null)
  const [history, setHistory] = useState<Analysis[]>([])
  const [selected, setSelected] = useState<AnalyzeResult | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  
  // 1. Nouveaux états
  const [emlFile, setEmlFile] = useState<File | null>(null)
  
  const [analyzing, setAnalyzing] = useState(false)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'alerts' | 'scanner' | 'sigma'>('alerts')
  const [pdfLoading, setPdfLoading] = useState(false)
  const [time, setTime] = useState('')

  // Clock
  useEffect(() => {
    const tick = () => setTime(new Date().toTimeString().slice(0, 8))
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  // Fetch core data
  const fetchAll = useCallback(async () => {
    try {
      const [h, s, hist] = await Promise.all([
        fetch(`${API}/health`).then(r => r.json()),
        fetch(`${API}/stats`).then(r => r.json()),
        fetch(`${API}/history?limit=20`).then(r => r.json()),
      ])
      setHealth(h)
      setStats(s)
      setHistory(hist)
    } catch (e) {
      console.error('Fetch error', e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchAll() }, [fetchAll])
  useEffect(() => {
    const id = setInterval(fetchAll, 15000)
    return () => clearInterval(id)
  }, [fetchAll])

  // Load detail
  const loadDetail = async (id: string) => {
    setSelectedId(id)
    try {
      const r = await fetch(`${API}/history/${id}`)
      const d = await r.json()
      setSelected(d.report_full)
    } catch (e) {
      console.error(e)
    }
  }

  // 2. Remplacement de la fonction analyze()
  const analyze = async () => {
    if (!emlFile) return
    setAnalyzing(true)
    try {
      const form = new FormData()
      form.append("file", emlFile)

      const r = await fetch(`${API}/analyze/eml`, {
        method: "POST",
        body: form,
      })

      const d: AnalyzeResult = await r.json()
      setSelected(d)
      setSelectedId(d.analysis_id)
      await fetchAll()
      setActiveTab("alerts")
    } catch (e) {
      console.error(e)
    } finally {
      setAnalyzing(false)
    }
  }

  // Download PDF
  const downloadPdf = async (id: string) => {
    setPdfLoading(true)
    try {
      const r = await fetch(`${API}/report/pdf/${id}`)
      const blob = await r.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `DASEC_report_${id.slice(0, 8)}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error(e)
    } finally {
      setPdfLoading(false)
    }
  }

  const phishingCount = stats?.by_verdict?.['PHISHING'] ?? 0
  const suspectCount = stats?.by_verdict?.['SUSPECT'] ?? 0
  const legitCount = stats?.by_verdict?.['LEGITIME'] ?? 0
  const ragOk = health ? Object.values(health.rag_collections).some(v => v > 0) : false

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gridTemplateRows: '44px 1fr', height: '100vh', overflow: 'hidden' }}>

      {/* Topbar */}
      <div style={{
        gridColumn: '1 / -1',
        display: 'flex', alignItems: 'center', gap: 16,
        padding: '0 20px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--surface)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <rect x="1" y="1" width="8" height="8" rx="1.5" fill="#3b82f6" opacity="0.9"/>
            <rect x="11" y="1" width="8" height="8" rx="1.5" fill="#3b82f6" opacity="0.4"/>
            <rect x="1" y="11" width="8" height="8" rx="1.5" fill="#3b82f6" opacity="0.4"/>
            <rect x="11" y="11" width="8" height="8" rx="1.5" fill="#ef4444" opacity="0.9"/>
          </svg>
          <span style={{ fontSize: 12, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>DASEC</span>
          <div style={{ width: 1, height: 16, background: 'var(--border-strong)' }} />
          <span style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.04em' }}>SOC Intelligence Platform</span>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
          {/* Live indicator */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{
              width: 6, height: 6, borderRadius: '50%',
              background: health?.status === 'ok' ? 'var(--green)' : 'var(--red)',
            }} />
            <span style={{ fontSize: 10, color: 'var(--green)', letterSpacing: '0.06em', fontWeight: 500 }}>
              {health?.status === 'ok' ? 'LIVE' : 'OFFLINE'}
            </span>
          </div>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--text-muted)' }}>{time}</span>
          {/* Status pills */}
          {health && (
            <>
              <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 3, background: ragOk ? 'var(--green-dim)' : 'var(--red-dim)', color: ragOk ? 'var(--green)' : 'var(--red)', fontWeight: 600 }}>
                RAG {ragOk ? 'OK' : 'KO'}
              </span>
              <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 3, background: 'var(--accent-dim)', color: 'var(--accent)', fontWeight: 600 }}>
                LLM {health.llm_backend || 'none'}
              </span>
            </>
          )}
          <button
            onClick={fetchAll}
            style={{ width: 28, height: 28, borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: 'var(--text-dim)' }}
            aria-label="Refresh"
          >
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      {/* Sidebar */}
      <nav style={{ background: 'var(--surface)', borderRight: '1px solid var(--border)', padding: '16px 0', overflowY: 'auto' }}>
        {[
          { label: 'Overview', items: [
            { icon: <Activity size={14}/>, label: 'Dashboard', tab: null },
            { icon: <AlertTriangle size={14}/>, label: 'Alerts', count: phishingCount + suspectCount, tab: 'alerts' as const },
            { icon: <Mail size={14}/>, label: 'Email scanner', tab: 'scanner' as const },
          ]},
          { label: 'Analysis', items: [
            { icon: <Shield size={14}/>, label: 'Sigma rules', tab: 'sigma' as const },
            { icon: <FileText size={14}/>, label: 'PDF reports', tab: null },
          ]},
          { label: 'Platform', items: [
            { icon: <Plug size={14}/>, label: 'SIEM connectors', tab: null },
            { icon: <Settings size={14}/>, label: 'Settings', tab: null },
          ]},
        ].map(section => (
          <div key={section.label}>
            <div style={{ padding: '12px 16px 4px', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', fontWeight: 600 }}>
              {section.label}
            </div>
            {section.items.map(item => (
              <div
                key={item.label}
                onClick={() => item.tab && setActiveTab(item.tab)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '7px 16px', cursor: 'pointer', fontSize: 12,
                  color: activeTab === item.tab ? 'var(--accent)' : 'var(--text-dim)',
                  borderLeft: `2px solid ${activeTab === item.tab ? 'var(--accent)' : 'transparent'}`,
                  background: activeTab === item.tab ? 'var(--accent-dim)' : 'transparent',
                }}
              >
                {item.icon}
                <span style={{ flex: 1 }}>{item.label}</span>
                {'count' in item && item.count ? (
                  <span style={{ fontSize: 9, fontWeight: 600, padding: '1px 5px', borderRadius: 3, background: 'var(--red-dim)', color: 'var(--red)' }}>
                    {item.count}
                  </span>
                ) : null}
              </div>
            ))}
          </div>
        ))}
      </nav>

      {/* Main */}
      <main style={{ overflowY: 'auto', background: 'var(--bg)', padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>

        {loading ? (
          <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>Connecting to DASEC API...</div>
        ) : (

          <>
            {/* Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
              {[
                { label: 'Total analyses', value: stats?.total_analyses ?? 0, color: 'var(--text)' },
                { label: 'Phishing', value: phishingCount, color: 'var(--red)' },
                { label: 'Suspect', value: suspectCount, color: 'var(--amber)' },
                { label: 'Legitimate', value: legitCount, color: 'var(--green)' },
                { label: 'Total IOCs', value: stats?.total_iocs ?? 0, color: 'var(--purple)' },
              ].map(m => (
                <div key={m.label} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '12px 14px' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 6 }}>{m.label}</div>
                  <div style={{ fontSize: 22, fontWeight: 600, fontFamily: 'JetBrains Mono, monospace', color: m.color, lineHeight: 1 }}>{m.value}</div>
                </div>
              ))}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 16 }}>

              {/* Left column */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

                {/* Tab bar */}
                <div style={{ display: 'flex', gap: 2, borderBottom: '1px solid var(--border)', paddingBottom: 0 }}>
                  {(['alerts', 'scanner', 'sigma'] as const).map(tab => (
                    <button
                      key={tab}
                      onClick={() => setActiveTab(tab)}
                      style={{
                        padding: '6px 14px', fontSize: 11, fontWeight: 500,
                        background: 'transparent', border: 'none', cursor: 'pointer',
                        color: activeTab === tab ? 'var(--accent)' : 'var(--text-muted)',
                        borderBottom: `2px solid ${activeTab === tab ? 'var(--accent)' : 'transparent'}`,
                        marginBottom: -1, fontFamily: 'Inter, sans-serif',
                        textTransform: 'capitalize',
                      }}
                    >
                      {tab === 'alerts' ? 'Alert feed' : tab === 'scanner' ? 'Email scanner' : 'Sigma rules'}
                    </button>
                  ))}
                </div>

                {/* Alert feed */}
                {activeTab === 'alerts' && (
                  <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
                    {history.length === 0 ? (
                      <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                        No analyses yet — use the email scanner to start
                      </div>
                    ) : history.map(a => (
                      <div
                        key={a.analysis_id}
                        onClick={() => loadDetail(a.analysis_id)}
                        style={{
                          display: 'flex', alignItems: 'flex-start', gap: 10,
                          padding: '10px 14px', borderBottom: '1px solid var(--border)',
                          cursor: 'pointer',
                          background: selectedId === a.analysis_id ? 'var(--surface-2)' : 'transparent',
                        }}
                      >
                        <div style={{ width: 3, borderRadius: 2, alignSelf: 'stretch', minHeight: 40, background: verdictColor(a.verdict) }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 12, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {a.subject || a.sender || 'No subject'}
                          </div>
                          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2, display: 'flex', gap: 8 }}>
                            <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, fontWeight: 600, background: a.verdict === 'PHISHING' ? 'var(--red-dim)' : a.verdict === 'SUSPECT' ? 'var(--amber-dim)' : 'var(--green-dim)', color: verdictColor(a.verdict) }}>
                              {a.verdict}
                            </span>
                            <span>{a.technique_attck?.slice(0, 20) || 'N/A'}</span>
                            <span>{new Date(a.analyzed_at).toLocaleTimeString()}</span>
                          </div>
                        </div>
                        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, fontWeight: 600, color: verdictColor(a.verdict), flexShrink: 0 }}>
                          {a.score_global.toFixed(2)}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* 3. Remplacement complet de l'Email Scanner */}
                {activeTab === 'scanner' && (
                  <div
                    style={{
                      background: 'var(--surface)',
                      border: '1px solid var(--border)',
                      borderRadius: 6,
                      padding: 20,
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 18,
                    }}
                  >
                    <h3 style={{ margin: 0 }}>Analyse d'un email (.eml)</h3>

                    <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
                      Déposez un email exporté (.eml). DASEC analysera automatiquement :
                    </p>

                    <ul style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 0, paddingLeft: 20, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 20px' }}>
                      <li>✓ Headers</li>
                      <li>✓ Corps HTML / Texte</li>
                      <li>✓ URLs</li>
                      <li>✓ OCR des images</li>
                      <li>✓ Pièces jointes</li>
                      <li>✓ Documents Office</li>
                      <li>✓ PDF</li>
                      <li>✓ NLP</li>
                      <li>✓ RAG</li>
                      <li>✓ Threat Intelligence</li>
                      <li>✓ Sigma Rules</li>
                    </ul>

                    <input
                      type="file"
                      accept=".eml"
                      onChange={(e) => {
                        if (e.target.files?.length) {
                          setEmlFile(e.target.files[0])
                        }
                      }}
                      style={{ fontSize: 12 }}
                    />

                    {emlFile && (
                      <div style={{
                        padding: 12,
                        border: '1px solid var(--border)',
                        borderRadius: 6,
                        background: 'var(--surface-2)',
                        fontSize: 12
                      }}>
                        <b>Fichier :</b>
                        <br />
                        {emlFile.name}
                        <br />
                        {(emlFile.size / 1024).toFixed(1)} KB
                      </div>
                    )}

                    <button
                      onClick={analyze}
                      disabled={!emlFile || analyzing}
                      style={{
                        padding: '10px',
                        borderRadius: 6,
                        cursor: !emlFile || analyzing ? 'not-allowed' : 'pointer',
                        background: analyzing ? 'var(--accent-dim)' : 'var(--accent)',
                        color: '#ffffff',
                        border: 'none',
                        fontWeight: 600,
                        fontSize: 12,
                        transition: 'opacity 0.2s'
                      }}
                    >
                      {analyzing ? "Analyse en cours..." : "Analyser le fichier .eml"}
                    </button>
                  </div>
                )}

                {/* Sigma rules */}
                {activeTab === 'sigma' && selected?.sigma_rules && (
                  <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
                    <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 11, fontWeight: 600 }}>{selected.sigma_rules.rules_count} rule(s) — ready to deploy</span>
                      <button
                        onClick={() => selectedId && downloadPdf(selectedId)}
                        style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid var(--accent)', background: 'transparent', color: 'var(--accent)', fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'Inter, sans-serif' }}
                      >
                        <Download size={11} /> Export PDF
                      </button>
                    </div>
                    <pre style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--text-dim)', lineHeight: 1.7, padding: 14, overflowX: 'auto', background: 'var(--surface-2)', margin: 0 }}>
                      {selected.sigma_rules.combined_yaml}
                    </pre>
                  </div>
                )}

                {/* 4 & 5. Affichage des détails avancés de l'analyse */}
                {selected && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                    
                    {/* 4. Carte "Informations Email" exigée */}
                    <div
                      style={{
                        background: 'var(--surface)',
                        border: '1px solid var(--border)',
                        borderRadius: 6,
                        padding: 16,
                      }}
                    >
                      <h3 style={{ margin: '0 0 12px 0', fontSize: 13, fontWeight: 600 }}>Informations Email</h3>
                      <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
                        <tbody>
                          <tr style={{ borderBottom: '1px solid var(--border)' }}>
                            <td style={{ padding: '6px 0', color: 'var(--text-muted)' }}><b>Verdict</b></td>
                            <td style={{ padding: '6px 0', fontWeight: 600, color: verdictColor(selected.verdict) }}>{selected.verdict}</td>
                          </tr>
                          <tr style={{ borderBottom: '1px solid var(--border)' }}>
                            <td style={{ padding: '6px 0', color: 'var(--text-muted)' }}><b>Score</b></td>
                            <td style={{ padding: '6px 0', fontFamily: 'JetBrains Mono, monospace' }}>{selected.score_global.toFixed(2)}</td>
                          </tr>
                          <tr style={{ borderBottom: '1px solid var(--border)' }}>
                            <td style={{ padding: '6px 0', color: 'var(--text-muted)' }}><b>Technique MITRE</b></td>
                            <td style={{ padding: '6px 0' }}>{selected.report?.technique_attck || 'N/A'}</td>
                          </tr>
                          <tr>
                            <td style={{ padding: '6px 0', color: 'var(--text-muted)' }}><b>Campagne</b></td>
                            <td style={{ padding: '6px 0' }}>{selected.report?.campagne_probable || 'Inconnue'}</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>

                    {/* 5. Modules Professionnels Additionnels issus du Moteur DASEC */}
                    
                    {/* Carte : Méta & Sécurité des En-têtes (From, To, SPF, DKIM, etc.) */}
                    {selected.email_meta && (
                      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12 }}>
                          <Mail size={14} color="var(--accent)" />
                          <h4 style={{ margin: 0, fontSize: 12 }}>En-têtes complets & Validation Sécurité</h4>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 11 }}>
                          <div><span style={{ color: 'var(--text-muted)' }}>From:</span> {selected.email_meta.from || 'N/A'}</div>
                          <div><span style={{ color: 'var(--text-muted)' }}>To:</span> {selected.email_meta.to || 'N/A'}</div>
                          <div><span style={{ color: 'var(--text-muted)' }}>Reply-To:</span> {selected.email_meta.reply_to || 'N/A'}</div>
                          <div><span style={{ color: 'var(--text-muted)' }}>Return-Path:</span> {selected.email_meta.return_path || 'N/A'}</div>
                        </div>
                        <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
                          {['spf', 'dkim', 'dmarc'].map((auth) => {
                            const val = selected.email_meta?.[auth as keyof typeof selected.email_meta];
                            const isPass = val?.toLowerCase() === 'pass';
                            return val ? (
                              <span key={auth} style={{ fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: isPass ? 'var(--green-dim)' : 'var(--red-dim)', color: isPass ? 'var(--green)' : 'var(--red)' }}>
                                {auth.toUpperCase()}: {val}
                              </span>
                            ) : null;
                          })}
                        </div>
                      </div>
                    )}

                    {/* Carte : Explication IA & Moteur Contextuel (Groq/LLM) */}
                    <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: 16 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                        <Cpu size={14} color="var(--purple)" />
                        <h4 style={{ margin: 0, fontSize: 12 }}>Analyse contextuelle & Explication LLM</h4>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.6, padding: 10, background: 'var(--surface-2)', borderRadius: 6 }}>
                        {selected.report?.explication}
                      </div>
                      {selected.report?.recommandation && (
                        <div style={{ marginTop: 8, fontSize: 11, borderLeft: '2px solid var(--green)', paddingLeft: 8, color: 'var(--text-muted)' }}>
                          <b>Recommandation SOC :</b> {selected.report.recommandation}
                        </div>
                      )}
                    </div>

                    {/* Carte : Évaluation Technique Globale (Scores) */}
                    <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: 14 }}>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
                        {[
                          { label: 'Global DASEC', value: selected.score_global },
                          { label: 'NLP / DistilBERT', value: selected.nlp?.bert_score },
                          { label: 'IoC Intelligence', value: selected.threat_intel?.score },
                          { label: 'Filtre URLs', value: selected.urls?.score },
                        ].map(s => (
                          <div key={s.label} style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 8px' }}>
                            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 2 }}>{s.label}</div>
                            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, fontWeight: 600, color: scoreColor(s.value ?? 0) }}>
                              {(s.value ?? 0).toFixed(2)}
                            </div>
                            <ScoreBar value={s.value ?? 0} color={scoreColor(s.value ?? 0)} />
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Carte : Pièces jointes détectées & Outils Analyse statique (oletools) */}
                    {selected.attachments && selected.attachments.length > 0 && (
                      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12 }}>
                          <Binary size={14} color="var(--amber)" />
                          <h4 style={{ margin: 0, fontSize: 12 }}>Pièces jointes & Analyse de Macros (oletools)</h4>
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          {selected.attachments.map((att, i) => (
                            <div key={i} style={{ fontSize: 11, padding: 8, background: 'var(--surface-2)', borderRadius: 6, border: att.oletools_macro_detected ? '1px solid var(--red-dim)' : '1px solid var(--border)' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 500 }}>
                                <span>📎 {att.filename} ({(att.size / 1024).toFixed(1)} KB)</span>
                                {att.oletools_macro_detected && (
                                  <span style={{ fontSize: 9, color: 'var(--red)', fontWeight: 700, background: 'var(--red-dim)', padding: '1px 4px', borderRadius: 3 }}>MACRO MALVEILLANTE</span>
                                )}
                              </div>
                              {att.oletools_findings && att.oletools_findings.length > 0 && (
                                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, fontFamily: 'JetBrains Mono, monospace', background: 'var(--surface-3)', padding: 6, borderRadius: 4 }}>
                                  {att.oletools_findings.map((f, fi) => <div key={fi}>↳ {f}</div>)}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Carte : Analyse OCR des images intégrées */}
                    {selected.ocr_results && selected.ocr_results.length > 0 && (
                      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                          <Eye size={14} color="var(--accent)" />
                          <h4 style={{ margin: 0, fontSize: 12 }}>Extraction OCR des Images</h4>
                        </div>
                        {selected.ocr_results.map((img, i) => (
                          <div key={i} style={{ fontSize: 11, background: 'var(--surface-2)', padding: 8, borderRadius: 6 }}>
                            <div style={{ fontWeight: 500, color: 'var(--text-muted)', marginBottom: 4 }}>🖼 {img.image_name} :</div>
                            <pre style={{ margin: 0, fontSize: 10, fontFamily: 'Inter, sans-serif', color: 'var(--text-dim)', whiteSpace: 'pre-wrap' }}>"{img.extracted_text}"</pre>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Carte : Contenu PDF extrait */}
                    {selected.pdf_content_extracted && selected.pdf_content_extracted.length > 0 && (
                      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                          <FileText size={14} color="var(--red)" />
                          <h4 style={{ margin: 0, fontSize: 12 }}>Contenu extrait des PDF joints</h4>
                        </div>
                        <div style={{ maxHeight: 100, overflowY: 'auto', fontSize: 10, background: 'var(--surface-2)', padding: 8, borderRadius: 6, fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-muted)' }}>
                          {selected.pdf_content_extracted.map((line, i) => <div key={i}>{line}</div>)}
                        </div>
                      </div>
                    )}

                    {/* Actions de téléchargement et d'export */}
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button
                        onClick={() => selectedId && downloadPdf(selectedId)}
                        disabled={pdfLoading}
                        style={{ padding: '6px 12px', borderRadius: 6, border: '1px solid var(--accent)', background: 'transparent', color: 'var(--accent)', fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'Inter, sans-serif' }}
                      >
                        <Download size={11} /> {pdfLoading ? 'Génération...' : 'Télécharger le rapport PDF'}
                      </button>
                      <button
                        onClick={() => setActiveTab('sigma')}
                        style={{ padding: '6px 12px', borderRadius: 6, border: '1px solid var(--border-strong)', background: 'transparent', color: 'var(--text)', fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'Inter, sans-serif' }}
                      >
                        <Shield size={11} /> Voir Règles Sigma
                      </button>
                    </div>

                  </div>
                )}
              </div>

              {/* Right column */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>

                {/* System status */}
                <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', fontSize: 11, fontWeight: 600 }}>System status</div>
                  {health && [
                    { label: 'API', ok: health.status === 'ok' },
                    { label: 'RAG / ChromaDB', ok: ragOk },
                    { label: `LLM (${health.llm_backend || 'none'})`, ok: !!health.llm_backend },
                    { label: 'VirusTotal', ok: health.threat_intel_apis?.virustotal },
                    { label: 'AbuseIPDB', ok: health.threat_intel_apis?.abuseipdb },
                    { label: 'SOC alerts', ok: health.soc_alert },
                  ].map(s => (
                    <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 14px', borderBottom: '1px solid var(--border)' }}>
                      <Circle size={6} fill={s.ok ? 'var(--green)' : 'var(--red)'} color={s.ok ? 'var(--green)' : 'var(--red)'} />
                      <span style={{ flex: 1, fontSize: 12 }}>{s.label}</span>
                      <span style={{ fontSize: 10, color: s.ok ? 'var(--green)' : 'var(--red)' }}>{s.ok ? 'ok' : 'ko'}</span>
                    </div>
                  ))}
                </div>

                {/* Top techniques */}
                {stats?.top_techniques?.length ? (
                  <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
                    <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', fontSize: 11, fontWeight: 600 }}>Top MITRE techniques</div>
                    {stats.top_techniques.map((t, i) => (
                      <div key={i} style={{ padding: '7px 14px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 9, fontFamily: 'JetBrains Mono, monospace', padding: '1px 5px', borderRadius: 3, background: 'var(--purple-dim)', color: 'var(--purple)', fontWeight: 600 }}>
                          {t.technique?.split(' ')[0] || 'N/A'}
                        </span>
                        <span style={{ flex: 1, fontSize: 11, color: 'var(--text-dim)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {t.technique?.slice(t.technique.indexOf(' ') + 1, 30) || t.technique}
                        </span>
                        <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-muted)' }}>{t.count}</span>
                      </div>
                    ))}
                  </div>
                ) : null}

                {/* IOC feed */}
                {selected?.report?.iocs && (
                  <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
                    <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', fontSize: 11, fontWeight: 600 }}>IOCs detected</div>
                    {[
                      ...selected.report.iocs.urls_suspectes.map(v => ({ type: 'URL', val: v, color: 'var(--accent)' })),
                      ...selected.report.iocs.ips_malveillantes.map(v => ({ type: 'IP', val: v, color: 'var(--red)' })),
                      ...selected.report.iocs.hashes.map(v => ({ type: 'HASH', val: v, color: 'var(--purple)' })),
                    ].slice(0, 6).map((ioc, i) => (
                      <div key={i} style={{ padding: '6px 14px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 9, fontWeight: 600, padding: '1px 5px', borderRadius: 3, background: `${ioc.color}20`, color: ioc.color, flexShrink: 0 }}>{ioc.type}</span>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--text-dim)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.val}</span>
                      </div>
                    ))}
                    {!selected.report.iocs.urls_suspectes.length && !selected.report.iocs.ips_malveillantes.length && (
                      <div style={{ padding: 12, fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>No IOCs detected</div>
                    )}
                  </div>
                )}

                {/* RAG status */}
                <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', fontSize: 11, fontWeight: 600 }}>Knowledge base</div>
                  {health && Object.entries(health.rag_collections).map(([name, count]) => (
                    <div key={name} style={{ padding: '6px 14px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ flex: 1, fontSize: 11, color: 'var(--text-dim)' }}>{name.replace(/_/g, ' ')}</span>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: count > 0 ? 'var(--green)' : 'var(--red)' }}>{count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>

              </div>
            </div>
          </>
        )}
      </main>
    </div>
  )
}