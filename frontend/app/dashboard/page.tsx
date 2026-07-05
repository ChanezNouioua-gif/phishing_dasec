'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Shield, AlertTriangle, Mail, FileText, Plug, RefreshCw,
  Settings, Activity, Download, Circle, Link, Eye,
  Binary, Cpu, ChevronRight, Search, Plus, Bell,
  BarChart2, Database, Globe, Hash, Lock, Zap, X
} from 'lucide-react'

const API = process.env.NEXT_PUBLIC_API_URL || 'https://chaneznouioua-gif-mailshield.hf.space'

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
  email_meta?: { from?: string; to?: string; reply_to?: string; return_path?: string; subject?: string; date?: string }
  modules?: {
    headers?: { score: number; spf_pass: boolean; dkim_pass: boolean; dmarc_pass: boolean; findings: string[]; ips_found: string[] }
    nlp?: { bert_score: number; lr_score: number; score: number; keywords: string[] }
    urls?: { score: number; suspicious: string[]; findings: string[]; total_urls: number }
    threat_intel?: { score: number; iocs_detected: string[] }
    images?: { score: number; ocr_text: string; images_count: number; findings: string[] }
    attachments?: { score: number; attachments_count: number; suspicious_hashes: Array<{ filename: string; sha256: string; size: number }>; findings: string[] }
    rag?: { techniques: Array<{ tech_id: string; name: string; tactics: string; similarity: number }>; apt_groups: Array<{ group_id: string; name: string; similarity: number }>; campaigns: Array<{ campaign: string; actor: string; severity: string; similarity: number }> }
  }
  nlp?: { bert_score: number; lr_score: number; score: number }
  urls?: { score: number; suspicious: string[]; findings: string[] }
  threat_intel?: { score: number; iocs_detected: string[] }
  rag?: { techniques: Array<{ tech_id: string; name: string; tactics: string; similarity: number }> }
  report: {
    confiance: string
    campagne_probable: string
    technique_attck: string
    vecteur_attaque: string
    indicateurs_cles: string[]
    explication: string
    recommandation: string
    iocs: { urls_suspectes: string[]; ips_malveillantes: string[]; hashes: string[] }
  }
  sigma_rules: { rules_count: number; combined_yaml: string; rules: Array<{ type: string; yaml: string }> }
}

// ── Helpers ────────────────────────────────────────────────────
const scoreColor = (s: number) => s >= 0.7 ? '#ef4444' : s >= 0.4 ? '#f59e0b' : '#22c55e'
const verdictColor = (v: string) => v === 'PHISHING' ? '#ef4444' : v === 'SUSPECT' ? '#f59e0b' : '#22c55e'
const verdictBg = (v: string) => v === 'PHISHING' ? '#ef444420' : v === 'SUSPECT' ? '#f59e0b20' : '#22c55e20'

function ScoreBar({ value, color, height = 3 }: { value: number; color: string; height?: number }) {
  return (
    <div style={{ height, background: '#1e293b', borderRadius: 2, overflow: 'hidden', marginTop: 6 }}>
      <div style={{ height: '100%', width: `${Math.round((value ?? 0) * 100)}%`, background: color, borderRadius: 2, transition: 'width 0.6s ease' }} />
    </div>
  )
}

function Pill({ children, color, bg }: { children: React.ReactNode; color: string; bg: string }) {
  return (
    <span style={{ fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 3, color, background: bg, letterSpacing: '0.04em', textTransform: 'uppercase' as const }}>
      {children}
    </span>
  )
}

// Spark bar chart for volume
function SparkBars({ data }: { data: number[] }) {
  const max = Math.max(...data, 1)
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 40 }}>
      {data.map((v, i) => (
        <div key={i} style={{ flex: 1, background: v > max * 0.7 ? '#ef4444' : '#3b82f6', borderRadius: '2px 2px 0 0', height: `${(v / max) * 100}%`, minHeight: 2, opacity: i === data.length - 1 ? 1 : 0.6 + (i / data.length) * 0.4 }} />
      ))}
    </div>
  )
}

// MITRE badge
function MitreBadge({ id }: { id: string }) {
  const colors = ['#3b82f6', '#8b5cf6', '#06b6d4', '#f59e0b', '#ef4444', '#10b981']
  const color = colors[id.charCodeAt(1) % colors.length]
  return (
    <span style={{ fontSize: 9, fontWeight: 700, padding: '2px 5px', borderRadius: 3, background: `${color}25`, color, border: `1px solid ${color}40`, fontFamily: 'monospace' }}>
      {id}
    </span>
  )
}

// SIEM connector row
function SiemRow({ name, status, rules }: { name: string; status: 'connected' | 'syncing' | 'offline'; rules: number }) {
  const statusColor = status === 'connected' ? '#22c55e' : status === 'syncing' ? '#f59e0b' : '#6b7280'
  const statusBg = status === 'connected' ? '#22c55e20' : status === 'syncing' ? '#f59e0b20' : '#6b728020'
  return (
    <div style={{ display: 'flex', alignItems: 'center', padding: '8px 14px', borderBottom: '1px solid #1e293b', gap: 10 }}>
      <span style={{ flex: 1, fontSize: 12, color: '#94a3b8' }}>{name}</span>
      <Pill color={statusColor} bg={statusBg}>{status}</Pill>
      <span style={{ fontSize: 11, color: '#64748b', fontFamily: 'monospace' }}>{rules} rules</span>
    </div>
  )
}

// Nav item
function NavItem({ icon, label, active, count, onClick }: { icon: React.ReactNode; label: string; active: boolean; count?: number; onClick?: () => void }) {
  return (
    <div onClick={onClick} style={{
      display: 'flex', alignItems: 'center', gap: 9, padding: '7px 16px', cursor: 'pointer', fontSize: 12,
      color: active ? '#3b82f6' : '#64748b',
      borderLeft: `2px solid ${active ? '#3b82f6' : 'transparent'}`,
      background: active ? '#3b82f620' : 'transparent',
      transition: 'all 0.15s',
    }}>
      {icon}
      <span style={{ flex: 1 }}>{label}</span>
      {count !== undefined && count > 0 && (
        <span style={{ fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 3, background: '#ef444420', color: '#ef4444' }}>{count}</span>
      )}
    </div>
  )
}

export default function Dashboard() {
  const [health, setHealth] = useState<HealthData | null>(null)
  const [stats, setStats] = useState<StatsData | null>(null)
  const [history, setHistory] = useState<Analysis[]>([])
  const [selected, setSelected] = useState<AnalyzeResult | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [emlFile, setEmlFile] = useState<File | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [loading, setLoading] = useState(true)
  const [activeNav, setActiveNav] = useState<'dashboard' | 'alerts' | 'scanner' | 'sigma' | 'ioc' | 'pdf' | 'feeds' | 'mitre' | 'apt'>('dashboard')
  const [pdfLoading, setPdfLoading] = useState(false)
  const [time, setTime] = useState('')
  const [sparkData] = useState(() => Array.from({ length: 24 }, () => Math.floor(Math.random() * 20)))
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const tick = () => setTime(new Date().toTimeString().slice(0, 8))
    tick(); const id = setInterval(tick, 1000); return () => clearInterval(id)
  }, [])

  const fetchAll = useCallback(async () => {
    try {
      const [h, s, hist] = await Promise.all([
        fetch(`${API}/health`).then(r => r.json()),
        fetch(`${API}/stats`).then(r => r.json()),
        fetch(`${API}/history?limit=20`).then(r => r.json()),
      ])
      setHealth(h); setStats(s); setHistory(hist)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { fetchAll() }, [fetchAll])
  useEffect(() => { const id = setInterval(fetchAll, 15000); return () => clearInterval(id) }, [fetchAll])

  const loadDetail = async (id: string) => {
    setSelectedId(id)
    try {
      const r = await fetch(`${API}/history/${id}`)
      const d = await r.json()
      setSelected(d.report_full)
      setActiveNav('alerts')
    } catch (e) { console.error(e) }
  }

  const analyze = async () => {
    if (!emlFile) return
    setAnalyzing(true)
    try {
      const form = new FormData()
      form.append('file', emlFile)
      const r = await fetch(`${API}/analyze/eml`, { method: 'POST', body: form })
      const d: AnalyzeResult = await r.json()
      setSelected(d); setSelectedId(d.analysis_id)
      await fetchAll(); setActiveNav('alerts')
    } catch (e) { console.error(e) }
    finally { setAnalyzing(false) }
  }

  const downloadPdf = async (id: string) => {
    setPdfLoading(true)
    try {
      const r = await fetch(`${API}/report/pdf/${id}`)
      const blob = await r.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url
      a.download = `DASEC_report_${id.slice(0, 8)}.pdf`; a.click()
      URL.revokeObjectURL(url)
    } catch (e) { console.error(e) }
    finally { setPdfLoading(false) }
  }

  const phishingCount = stats?.by_verdict?.['PHISHING'] ?? 0
  const suspectCount = stats?.by_verdict?.['SUSPECT'] ?? 0
  const legitCount = stats?.by_verdict?.['LEGITIME'] ?? 0
  const ragOk = health ? Object.values(health.rag_collections).some(v => v > 0) : false

  // Derive module scores from selected
  const nlp = selected?.modules?.nlp ?? selected?.nlp
  const urls = selected?.modules?.urls ?? selected?.urls
  const ti = selected?.modules?.threat_intel ?? selected?.threat_intel
  const headers = selected?.modules?.headers
  const rag = selected?.modules?.rag ?? selected?.rag

  // Static MITRE techniques for coverage matrix
  const mitreMatrix = [
    'T1566.001','T1566.002','T1036','T1204.002','T1027',
    'T1078','T1539','T1114','T1598','T1071','T1056','T1497',
  ]

  // Static SIEM data
  const siemConnectors = [
    { name: 'Elastic SIEM', status: 'connected' as const, rules: health ? Math.floor(Object.values(health.rag_collections).reduce((a,b)=>a+b,0)/3) || 312 : 312 },
    { name: 'Splunk Enterprise', status: 'connected' as const, rules: 198 },
    { name: 'Microsoft Sentinel', status: 'connected' as const, rules: 87 },
    { name: 'IBM QRadar', status: 'syncing' as const, rules: 44 },
  ]

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gridTemplateRows: '44px 1fr', height: '100vh', overflow: 'hidden', background: '#0a0f1a', color: '#e2e8f0', fontFamily: 'Inter, system-ui, sans-serif' }}>

      {/* ── Topbar ── */}
      <div style={{ gridColumn: '1/-1', display: 'flex', alignItems: 'center', gap: 16, padding: '0 20px', borderBottom: '1px solid #1e293b', background: '#0d1424' }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ position: 'relative', width: 22, height: 22 }}>
            <div style={{ position: 'absolute', inset: 0, borderRadius: '50%', background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Shield size={13} color="#fff" strokeWidth={2.5} />
            </div>
            <div style={{ position: 'absolute', bottom: -2, right: -2, width: 8, height: 8, borderRadius: '50%', background: '#ef4444', border: '1.5px solid #0d1424' }} />
          </div>
          <span style={{ fontSize: 13, fontWeight: 700, letterSpacing: '0.1em', color: '#f1f5f9' }}>MailShield</span>
          <div style={{ width: 1, height: 16, background: '#1e293b' }} />
          <span style={{ fontSize: 10, color: '#475569', letterSpacing: '0.04em' }}>SOC Intelligence Platform</span>
        </div>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: health?.status === 'ok' ? '#22c55e' : '#ef4444', boxShadow: `0 0 6px ${health?.status === 'ok' ? '#22c55e' : '#ef4444'}` }} />
            <span style={{ fontSize: 10, color: '#22c55e', letterSpacing: '0.08em', fontWeight: 600 }}>
              {health?.status === 'ok' ? 'LIVE' : 'OFFLINE'}
            </span>
          </div>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: '#475569' }}>{time}</span>
          {health && <>
            <Pill color={ragOk ? '#22c55e' : '#ef4444'} bg={ragOk ? '#22c55e20' : '#ef444420'}>RAG {ragOk ? 'OK' : 'KO'}</Pill>
            <Pill color='#3b82f6' bg='#3b82f620'>LLM {health.llm_backend || 'none'}</Pill>
          </>}
          <button onClick={() => setActiveNav('scanner')} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 10px', borderRadius: 5, border: '1px solid #3b82f6', background: '#3b82f615', color: '#3b82f6', fontSize: 10, cursor: 'pointer', fontWeight: 600, letterSpacing: '0.04em' }}>
            <Plus size={11} /> Scan email
          </button>
          <button onClick={fetchAll} style={{ width: 28, height: 28, borderRadius: 6, border: '1px solid #1e293b', background: 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: '#475569' }}>
            <RefreshCw size={12} />
          </button>
        </div>
      </div>

      {/* ── Sidebar ── */}
      <nav style={{ background: '#0d1424', borderRight: '1px solid #1e293b', padding: '12px 0', overflowY: 'auto' }}>
        <div style={{ padding: '8px 16px 4px', fontSize: 9, color: '#334155', letterSpacing: '0.12em', textTransform: 'uppercase', fontWeight: 600 }}>Overview</div>
        <NavItem icon={<Activity size={13}/>} label="Dashboard" active={activeNav==='dashboard'} onClick={() => setActiveNav('dashboard')} />
        <NavItem icon={<AlertTriangle size={13}/>} label="Alerts" active={activeNav==='alerts'} count={phishingCount+suspectCount} onClick={() => setActiveNav('alerts')} />
        <NavItem icon={<Mail size={13}/>} label="Email scanner" active={activeNav==='scanner'} onClick={() => setActiveNav('scanner')} />

        <div style={{ padding: '12px 16px 4px', fontSize: 9, color: '#334155', letterSpacing: '0.12em', textTransform: 'uppercase', fontWeight: 600 }}>Analysis</div>
        <NavItem icon={<Shield size={13}/>} label="Sigma rules" active={activeNav==='sigma'} onClick={() => setActiveNav('sigma')} />
        <NavItem icon={<Search size={13}/>} label="IOC tracker" active={activeNav==='ioc'} onClick={() => setActiveNav('ioc')} />
        <NavItem icon={<FileText size={13}/>} label="PDF reports" active={activeNav==='pdf'} onClick={() => setActiveNav('pdf')} />

        <div style={{ padding: '12px 16px 4px', fontSize: 9, color: '#334155', letterSpacing: '0.12em', textTransform: 'uppercase', fontWeight: 600 }}>Intelligence</div>
        <NavItem icon={<Globe size={13}/>} label="Threat feeds" active={activeNav==='feeds'} onClick={() => setActiveNav('feeds')} />
        <NavItem icon={<Database size={13}/>} label="MITRE ATT&CK" active={activeNav==='mitre'} onClick={() => setActiveNav('mitre')} />
        <NavItem icon={<Binary size={13}/>} label="APT groups" active={activeNav==='apt'} count={2} onClick={() => setActiveNav('apt')} />

        <div style={{ padding: '12px 16px 4px', fontSize: 9, color: '#334155', letterSpacing: '0.12em', textTransform: 'uppercase', fontWeight: 600 }}>Integrations</div>
        <NavItem icon={<Plug size={13}/>} label="SIEM connectors" active={false} />
        <NavItem icon={<Hash size={13}/>} label="API" active={false} />
        <NavItem icon={<Settings size={13}/>} label="Audit log" active={false} />
      </nav>

      {/* ── Main ── */}
      <main style={{ overflowY: 'auto', background: '#080d16', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#475569', fontSize: 12, padding: 20 }}>
            <RefreshCw size={14} style={{ animation: 'spin 1s linear infinite' }} /> Connecting to DASEC API...
          </div>
        ) : (
          <>
            {/* ── KPI row ── */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
              {[
                { label: 'Threats today', value: phishingCount + suspectCount, sub: `↑${Math.max(0,phishingCount-2)} vs yesterday`, subColor: '#ef4444', barColor: '#ef4444', barVal: (phishingCount+suspectCount)/Math.max(stats?.total_analyses??1,1) },
                { label: 'Emails scanned', value: stats?.total_analyses ?? 0, sub: `↑3% vs avg`, subColor: '#3b82f6', barColor: '#3b82f6', barVal: 0.6 },
                { label: 'Detection rate', value: stats?.total_analyses ? `${((phishingCount+suspectCount)/stats.total_analyses*100).toFixed(1)}%` : '—', sub: '↑0.2% this week', subColor: '#22c55e', barColor: '#22c55e', barVal: (phishingCount+suspectCount)/Math.max(stats?.total_analyses??1,1) },
                { label: 'Legitimate', value: legitCount, sub: 'confirmed clean', subColor: '#22c55e', barColor: '#22c55e', barVal: legitCount/Math.max(stats?.total_analyses??1,1) },
                { label: 'Total IOCs', value: stats?.total_iocs ?? 0, sub: 'URLs · IPs · hashes', subColor: '#8b5cf6', barColor: '#8b5cf6', barVal: 0.4 },
              ].map(m => (
                <div key={m.label} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, padding: '12px 14px' }}>
                  <div style={{ fontSize: 10, color: '#475569', marginBottom: 4 }}>{m.label}</div>
                  <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: m.barColor, lineHeight: 1.1 }}>{m.value}</div>
                  <div style={{ fontSize: 9, color: m.subColor, marginTop: 3 }}>{m.sub}</div>
                  <ScoreBar value={m.barVal} color={m.barColor} height={2} />
                </div>
              ))}
            </div>

            {/* ── Two-column layout ── */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 14 }}>

              {/* ── Left ── */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

                {/* Tab bar */}
                <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid #1e293b' }}>
                  {[
                    { id: 'alerts', label: 'Live alert feed' },
                    { id: 'scanner', label: 'Email scanner' },
                    { id: 'sigma', label: 'Sigma rules' },
                  ].map(t => (
                    <button key={t.id} onClick={() => setActiveNav(t.id as any)} style={{
                      padding: '7px 16px', fontSize: 11, fontWeight: 500, background: 'transparent', border: 'none', cursor: 'pointer',
                      color: activeNav === t.id ? '#3b82f6' : '#475569',
                      borderBottom: `2px solid ${activeNav === t.id ? '#3b82f6' : 'transparent'}`,
                      marginBottom: -1, fontFamily: 'Inter, sans-serif',
                    }}>{t.label}</button>
                  ))}
                  <span style={{ marginLeft: 'auto', fontSize: 10, color: '#334155', alignSelf: 'center', paddingRight: 4 }}>auto-refresh 15s</span>
                </div>

                {/* ── Alert feed ── */}
                {activeNav === 'alerts' && (
                  <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, overflow: 'hidden' }}>
                    {history.length === 0 ? (
                      <div style={{ padding: 32, textAlign: 'center', color: '#475569', fontSize: 12 }}>
                        No analyses yet — use the email scanner to start
                      </div>
                    ) : history.map(a => (
                      <div key={a.analysis_id} onClick={() => loadDetail(a.analysis_id)} style={{
                        display: 'flex', alignItems: 'flex-start', gap: 10, padding: '11px 14px',
                        borderBottom: '1px solid #1e293b', cursor: 'pointer',
                        background: selectedId === a.analysis_id ? '#1e293b' : 'transparent',
                        transition: 'background 0.1s',
                      }}>
                        <div style={{ width: 3, borderRadius: 2, alignSelf: 'stretch', minHeight: 36, background: verdictColor(a.verdict), flexShrink: 0 }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 12, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#e2e8f0' }}>
                            {a.subject || a.sender || 'No subject'}
                          </div>
                          <div style={{ fontSize: 10, color: '#475569', marginTop: 3, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' as const }}>
                            <Pill color={verdictColor(a.verdict)} bg={verdictBg(a.verdict)}>{a.verdict}</Pill>
                            {a.verdict === 'PHISHING' && <Pill color="#ef4444" bg="#ef444415">CRITICAL</Pill>}
                            {a.verdict === 'SUSPECT' && <Pill color="#f59e0b" bg="#f59e0b15">HIGH</Pill>}
                            {a.verdict === 'LEGITIME' && <Pill color="#22c55e" bg="#22c55e15">CLEAN</Pill>}
                            <span style={{ color: '#334155' }}>{a.technique_attck?.slice(0, 22) || 'N/A'}</span>
                            <span style={{ color: '#1e3a5f' }}>·</span>
                            <span style={{ color: '#334155' }}>{new Date(a.analyzed_at).toLocaleTimeString()}</span>
                          </div>
                        </div>
                        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, fontWeight: 700, color: verdictColor(a.verdict), flexShrink: 0 }}>
                          {a.score_global.toFixed(2)}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* ── Scanner ── */}
                {activeNav === 'scanner' && (
                  <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Mail size={16} color="#3b82f6" />
                      <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600 }}>Email Analysis Engine</h3>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, fontSize: 11, color: '#475569' }}>
                      {['Headers SMTP','Corps HTML/Texte','URLs & domaines','OCR images','Pièces jointes','Macros VBA','NLP DistilBERT','RAG MITRE','Threat Intelligence','Règles Sigma'].map(f => (
                        <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                          <div style={{ width: 4, height: 4, borderRadius: '50%', background: '#22c55e', flexShrink: 0 }} /> {f}
                        </div>
                      ))}
                    </div>

                    <div
                      onClick={() => fileRef.current?.click()}
                      onDragOver={e => e.preventDefault()}
                      onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f?.name.endsWith('.eml')) setEmlFile(f) }}
                      style={{ border: `2px dashed ${emlFile ? '#3b82f6' : '#1e3a5f'}`, borderRadius: 7, padding: '24px 16px', textAlign: 'center', cursor: 'pointer', background: emlFile ? '#3b82f608' : 'transparent', transition: 'all 0.2s' }}
                    >
                      {emlFile ? (
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
                          <Mail size={16} color="#3b82f6" />
                          <div style={{ textAlign: 'left' }}>
                            <div style={{ fontSize: 12, fontWeight: 500, color: '#e2e8f0' }}>{emlFile.name}</div>
                            <div style={{ fontSize: 10, color: '#475569' }}>{(emlFile.size/1024).toFixed(1)} KB · prêt à analyser</div>
                          </div>
                          <button onClick={e => { e.stopPropagation(); setEmlFile(null) }} style={{ marginLeft: 8, background: 'none', border: 'none', cursor: 'pointer', color: '#475569' }}><X size={13}/></button>
                        </div>
                      ) : (
                        <>
                          <Mail size={20} color="#334155" style={{ marginBottom: 8 }} />
                          <div style={{ fontSize: 12, color: '#475569' }}>Déposer un fichier .eml ici</div>
                          <div style={{ fontSize: 10, color: '#334155', marginTop: 3 }}>ou cliquer pour sélectionner</div>
                        </>
                      )}
                    </div>
                    <input ref={fileRef} type="file" accept=".eml" style={{ display: 'none' }} onChange={e => { if (e.target.files?.[0]) setEmlFile(e.target.files[0]) }} />

                    <button onClick={analyze} disabled={!emlFile || analyzing} style={{
                      padding: '10px', borderRadius: 6, border: 'none', fontWeight: 600, fontSize: 12,
                      background: analyzing ? '#1e3a5f' : emlFile ? '#2563eb' : '#1e293b',
                      color: emlFile ? '#fff' : '#475569', cursor: emlFile && !analyzing ? 'pointer' : 'not-allowed',
                      display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, transition: 'all 0.2s',
                    }}>
                      {analyzing ? <><RefreshCw size={13} style={{ animation: 'spin 1s linear infinite' }} /> Analyse en cours...</> : <><Zap size={13}/> Analyser le fichier .eml</>}
                    </button>
                  </div>
                )}

                {/* ── Sigma ── */}
                {activeNav === 'sigma' && selected?.sigma_rules && (
                  <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, overflow: 'hidden' }}>
                    <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e293b', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 11, fontWeight: 600 }}>{selected.sigma_rules.rules_count} rule(s) — ready to deploy</span>
                      <button onClick={() => selectedId && downloadPdf(selectedId)} style={{ padding: '4px 10px', borderRadius: 5, border: '1px solid #3b82f6', background: 'transparent', color: '#3b82f6', fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
                        <Download size={11} /> Export PDF
                      </button>
                    </div>
                    <pre style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#64748b', lineHeight: 1.8, padding: 14, overflowX: 'auto', background: '#0a1120', margin: 0 }}>
                      {selected.sigma_rules.combined_yaml.split('\n').map((line, i) => {
                        const isKey = /^[a-z_]+:/.test(line.trim())
                        const isTag = line.trim().startsWith('- attack.')
                        const isTitle = line.trim().startsWith('title:')
                        const color = isTitle ? '#3b82f6' : isKey ? '#22c55e' : isTag ? '#f59e0b' : '#475569'
                        return <span key={i} style={{ color, display: 'block' }}>{line}</span>
                      })}
                    </pre>
                  </div>
                )}

                {/* ── Selected analysis detail ── */}
                {selected && activeNav === 'alerts' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>

                    {/* Active threat card */}
                    <div style={{ background: '#0d1424', border: `1px solid ${verdictColor(selected.verdict)}30`, borderRadius: 7, padding: 16 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                        <div>
                          <div style={{ fontSize: 11, color: '#475569', marginBottom: 2 }}>Active threat analysis</div>
                          <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>{selected.report?.campagne_probable || 'Unknown campaign'}</div>
                          {selected.email_meta && (
                            <div style={{ fontSize: 10, color: '#475569', marginTop: 3 }}>
                              {selected.email_meta.from && `From: ${selected.email_meta.from}`}
                              {selected.email_meta.subject && ` · Subject: ${selected.email_meta.subject}`}
                            </div>
                          )}
                        </div>
                        <div style={{ textAlign: 'right' }}>
                          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 28, fontWeight: 700, color: verdictColor(selected.verdict), lineHeight: 1 }}>
                            {selected.score_global.toFixed(2)}
                          </div>
                          <div style={{ fontSize: 9, color: '#475569', marginTop: 2 }}>risk score</div>
                          <Pill color={verdictColor(selected.verdict)} bg={verdictBg(selected.verdict)}>{selected.verdict}</Pill>
                        </div>
                      </div>

                      {/* Module scores */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginTop: 8 }}>
                        {[
                          { label: 'DistilBERT', value: nlp?.bert_score ?? 0, color: '#ef4444' },
                          { label: 'IoC score', value: ti?.score ?? 0, color: '#f59e0b' },
                          { label: 'RAG match', value: rag?.techniques?.[0]?.similarity ?? 0, color: '#8b5cf6' },
                          { label: 'Header', value: headers?.score ?? 0, color: '#3b82f6' },
                        ].map(s => (
                          <div key={s.label} style={{ background: '#0a1120', borderRadius: 6, padding: '8px 10px' }}>
                            <div style={{ fontSize: 9, color: '#475569', marginBottom: 3 }}>{s.label}</div>
                            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 15, fontWeight: 700, color: s.color }}>{s.value.toFixed(2)}</div>
                            <ScoreBar value={s.value} color={s.color} height={2} />
                          </div>
                        ))}
                      </div>

                      {/* LLM explanation */}
                      <div style={{ marginTop: 10, padding: 10, background: '#0a1120', borderRadius: 6, fontSize: 11, color: '#64748b', lineHeight: 1.6 }}>
                        {selected.report?.explication}
                      </div>

                      {/* Actions */}
                      <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                        {selected.verdict === 'PHISHING' && (
                          <button style={{ padding: '6px 14px', borderRadius: 5, border: '1px solid #ef444460', background: '#ef444415', color: '#ef4444', fontSize: 11, fontWeight: 600, cursor: 'pointer' }}>
                            Block & quarantine
                          </button>
                        )}
                        <button onClick={() => selectedId && downloadPdf(selectedId)} disabled={pdfLoading} style={{ padding: '6px 14px', borderRadius: 5, border: '1px solid #3b82f660', background: 'transparent', color: '#3b82f6', fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5 }}>
                          <Download size={11} /> {pdfLoading ? 'Génération...' : 'Export PDF'}
                        </button>
                        <button onClick={() => setActiveNav('sigma')} style={{ padding: '6px 14px', borderRadius: 5, border: '1px solid #1e293b', background: 'transparent', color: '#64748b', fontSize: 11, cursor: 'pointer' }}>
                          Push to SIEM
                        </button>
                      </div>
                    </div>

                    {/* Headers */}
                    {headers && (
                      <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, padding: 14 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                          <Lock size={12} color="#3b82f6" />
                          <span style={{ fontSize: 11, fontWeight: 600 }}>Header authentication</span>
                        </div>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' as const }}>
                          {[
                            { label: 'SPF', ok: headers.spf_pass },
                            { label: 'DKIM', ok: headers.dkim_pass },
                            { label: 'DMARC', ok: headers.dmarc_pass },
                          ].map(a => (
                            <span key={a.label} style={{ fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 4, background: a.ok ? '#22c55e20' : '#ef444420', color: a.ok ? '#22c55e' : '#ef4444', border: `1px solid ${a.ok ? '#22c55e40' : '#ef444440'}` }}>
                              {a.label}: {a.ok ? 'PASS' : 'FAIL'}
                            </span>
                          ))}
                        </div>
                        {headers.findings.length > 0 && (
                          <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 3 }}>
                            {headers.findings.map((f, i) => (
                              <div key={i} style={{ fontSize: 10, color: '#f59e0b', display: 'flex', alignItems: 'center', gap: 5 }}>
                                <div style={{ width: 3, height: 3, borderRadius: '50%', background: '#f59e0b', flexShrink: 0 }} /> {f}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Recommendation */}
                    {selected.report?.recommandation && (
                      <div style={{ background: '#0d1424', border: '1px solid #22c55e30', borderRadius: 7, padding: 12, display: 'flex', gap: 10 }}>
                        <div style={{ width: 3, borderRadius: 2, background: '#22c55e', flexShrink: 0 }} />
                        <div>
                          <div style={{ fontSize: 10, color: '#22c55e', fontWeight: 600, marginBottom: 3 }}>SOC RECOMMENDATION</div>
                          <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.5 }}>{selected.report.recommandation}</div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* ── Right column ── */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>

                {/* Monitored enterprises / System status */}
                <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e293b', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: 11, fontWeight: 600 }}>System status</span>
                    <button style={{ fontSize: 10, color: '#3b82f6', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3 }}>
                      <Plus size={10} /> Add
                    </button>
                  </div>
                  {health && [
                    { label: 'API backend', ok: health.status === 'ok', detail: health.status },
                    { label: 'RAG / ChromaDB', ok: ragOk, detail: ragOk ? `${Object.values(health.rag_collections).reduce((a,b)=>a+b,0).toLocaleString()} docs` : 'empty' },
                    { label: `LLM (${health.llm_backend||'none'})`, ok: !!health.llm_backend, detail: health.llm_backend||'offline' },
                    { label: 'VirusTotal', ok: health.threat_intel_apis?.virustotal, detail: health.threat_intel_apis?.virustotal ? 'active' : 'no key' },
                    { label: 'AbuseIPDB', ok: health.threat_intel_apis?.abuseipdb, detail: health.threat_intel_apis?.abuseipdb ? 'active' : 'no key' },
                    { label: 'URLHaus feed', ok: (health.ioc_feeds?.urlhaus ?? 0) > 0, detail: `${(health.ioc_feeds?.urlhaus ?? 0).toLocaleString()} IoCs` },
                    { label: 'OpenPhish feed', ok: (health.ioc_feeds?.openphish ?? 0) > 0, detail: `${(health.ioc_feeds?.openphish ?? 0).toLocaleString()} URLs` },
                  ].map(s => (
                    <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 14px', borderBottom: '1px solid #0f172a' }}>
                      <Circle size={5} fill={s.ok ? '#22c55e' : '#ef4444'} color={s.ok ? '#22c55e' : '#ef4444'} />
                      <span style={{ flex: 1, fontSize: 11, color: '#94a3b8' }}>{s.label}</span>
                      <span style={{ fontSize: 10, color: s.ok ? '#22c55e' : '#ef4444', fontFamily: 'monospace' }}>{s.detail}</span>
                    </div>
                  ))}
                </div>

                {/* SIEM connectors */}
                <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e293b', fontSize: 11, fontWeight: 600 }}>SIEM connectors</div>
                  {siemConnectors.map(s => <SiemRow key={s.name} {...s} />)}
                </div>

                {/* Top MITRE techniques */}
                {stats?.top_techniques?.length ? (
                  <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, overflow: 'hidden' }}>
                    <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e293b', fontSize: 11, fontWeight: 600 }}>Top MITRE techniques</div>
                    {stats.top_techniques.map((t, i) => (
                      <div key={i} style={{ padding: '7px 14px', borderBottom: '1px solid #0f172a', display: 'flex', alignItems: 'center', gap: 8 }}>
                        <MitreBadge id={t.technique?.split(' ')[0] || 'N/A'} />
                        <span style={{ flex: 1, fontSize: 10, color: '#475569', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const }}>
                          {t.technique?.includes(' ') ? t.technique.slice(t.technique.indexOf(' ')+1, 28) : t.technique}
                        </span>
                        <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#334155' }}>{t.count}</span>
                      </div>
                    ))}
                  </div>
                ) : null}

                {/* IOC tracker */}
                {selected?.report?.iocs && (
                  <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, overflow: 'hidden' }}>
                    <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e293b', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 11, fontWeight: 600 }}>IOC tracker</span>
                      <button style={{ fontSize: 10, color: '#3b82f6', background: 'none', border: 'none', cursor: 'pointer' }}>Search</button>
                    </div>
                    {[
                      ...selected.report.iocs.urls_suspectes.map(v => ({ type: 'URL', val: v, color: '#3b82f6', src: ti?.iocs_detected?.some(d => d.includes(v.slice(0,20))) ? `VT ${ti.score > 0 ? Math.round(ti.score*92)+'/92' : ''}` : 'pipeline' })),
                      ...selected.report.iocs.ips_malveillantes.map(v => ({ type: 'IP', val: v, color: '#ef4444', src: 'AbuseIPDB' })),
                      ...selected.report.iocs.hashes.map(v => ({ type: 'HASH', val: v, color: '#8b5cf6', src: 'VirusTotal' })),
                    ].slice(0, 5).map((ioc, i) => (
                      <div key={i} style={{ padding: '7px 14px', borderBottom: '1px solid #0f172a', display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 9, fontWeight: 700, padding: '2px 5px', borderRadius: 3, background: `${ioc.color}20`, color: ioc.color, flexShrink: 0 }}>{ioc.type}</span>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#475569', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const }}>{ioc.val}</span>
                        <span style={{ fontSize: 9, color: '#334155', flexShrink: 0 }}>{ioc.src}</span>
                      </div>
                    ))}
                    {!selected.report.iocs.urls_suspectes.length && !selected.report.iocs.ips_malveillantes.length && !selected.report.iocs.hashes.length && (
                      <div style={{ padding: 12, fontSize: 11, color: '#334155', textAlign: 'center' }}>No IOCs detected</div>
                    )}
                  </div>
                )}

                {/* MITRE ATT&CK coverage */}
                <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e293b', fontSize: 11, fontWeight: 600 }}>MITRE ATT&CK coverage</div>
                  <div style={{ padding: '10px 14px', display: 'flex', flexWrap: 'wrap' as const, gap: 4 }}>
                    {mitreMatrix.map(t => {
                      const isActive = stats?.top_techniques?.some(x => x.technique?.startsWith(t))
                      const isDetected = selected?.report?.technique_attck?.includes(t.split('.')[0])
                      return (
                        <span key={t} style={{ fontSize: 8, fontWeight: 600, padding: '2px 4px', borderRadius: 2, fontFamily: 'monospace', background: isDetected ? '#ef444425' : isActive ? '#3b82f620' : '#1e293b', color: isDetected ? '#ef4444' : isActive ? '#3b82f6' : '#334155', border: `1px solid ${isDetected ? '#ef444440' : isActive ? '#3b82f630' : 'transparent'}` }}>
                          {t}
                        </span>
                      )
                    })}
                  </div>
                  <div style={{ padding: '6px 14px 10px', display: 'flex', gap: 12 }}>
                    {[['#ef4444','Active now'],['#3b82f6','Detected this week'],['#334155','Monitored']].map(([c,l]) => (
                      <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <div style={{ width: 6, height: 6, borderRadius: 1, background: c }} />
                        <span style={{ fontSize: 9, color: '#334155' }}>{l}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Volume chart */}
                <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e293b', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: 11, fontWeight: 600 }}>Volume — last 12h</span>
                    <BarChart2 size={12} color="#334155" />
                  </div>
                  <div style={{ padding: '10px 14px 6px' }}>
                    <SparkBars data={sparkData.slice(-24)} />
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: 9, color: '#334155' }}>
                      <span>00:00</span><span>06:00</span><span>12:00</span><span>now</span>
                    </div>
                  </div>
                  <div style={{ padding: '8px 14px 10px', display: 'flex', gap: 14 }}>
                    {[['Peak', Math.max(...sparkData), '#ef4444'],['Total', stats?.total_analyses ?? 0, '#e2e8f0'],['Blocked', phishingCount, '#22c55e']].map(([l,v,c]) => (
                      <div key={l as string}>
                        <div style={{ fontSize: 9, color: '#334155' }}>{l}</div>
                        <div style={{ fontSize: 14, fontWeight: 700, fontFamily: 'monospace', color: c as string }}>{v}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Knowledge base */}
                <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 7, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e293b', fontSize: 11, fontWeight: 600 }}>Knowledge base</div>
                  {health && Object.entries(health.rag_collections).map(([name, count]) => (
                    <div key={name} style={{ padding: '6px 14px', borderBottom: '1px solid #0f172a', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ flex: 1, fontSize: 10, color: '#475569' }}>{name.replace(/_/g,' ')}</span>
                      <span style={{ fontFamily: 'monospace', fontSize: 10, color: count > 0 ? '#22c55e' : '#ef4444' }}>{count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>

              </div>
            </div>
          </>
        )}
      </main>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #0a0f1a; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 2px; }
      `}</style>
    </div>
  )
}
