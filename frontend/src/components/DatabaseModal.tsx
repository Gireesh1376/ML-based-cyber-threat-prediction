import { useState, useEffect } from 'react'
import { 
  Database, 
  X, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  ExternalLink, 
  Terminal, 
  FileCode2, 
  Copy, 
  Check,
  Server,
  Layers
} from 'lucide-react'
import { getDbStatus, getAlerts, type DbStatus, type AlertItem } from '../api'

interface DatabaseModalProps {
  isOpen: boolean
  onClose: () => void
}

export function DatabaseModal({ isOpen, onClose }: DatabaseModalProps) {
  const [status, setStatus] = useState<DbStatus | null>(null)
  const [loading, setLoading] = useState(false)
  const [sampleAlert, setSampleAlert] = useState<AlertItem | null>(null)
  const [activeTab, setActiveTab] = useState<'health' | 'sample' | 'queries'>('health')
  const [copied, setCopied] = useState<string | null>(null)

  const fetchStatus = async () => {
    setLoading(true)
    try {
      const [dbRes, alertsRes] = await Promise.all([
        getDbStatus(),
        getAlerts({ limit: 1 }).catch(() => null)
      ])
      setStatus(dbRes)
      if (alertsRes && alertsRes.items.length > 0) {
        setSampleAlert(alertsRes.items[0])
      }
    } catch {
      setStatus({ connected: false, error: 'Could not connect to Elasticsearch' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (isOpen) {
      fetchStatus()
    }
  }, [isOpen])

  // ESC to close
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  if (!isOpen) return null

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(null), 2000)
  }

  const curlQuery = `curl -X GET "http://localhost:9200/aegis-alerts/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": { "match_all": {} },
  "size": 5,
  "sort": [{ "priority": "desc" }]
}'`

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-fade-in">
      <div 
        className="w-full max-w-3xl glass-card rounded-2xl border border-white/10 shadow-2xl overflow-hidden flex flex-col max-h-[88vh] bg-[#0c121e]/95 text-slate-100"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-white/8 flex items-center justify-between bg-white/[0.02]">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
              <Database size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-wide">Elasticsearch Database Hub</h2>
                {status?.connected ? (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Connected
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-rose-500/15 text-rose-400 border border-rose-500/30">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                    Offline (Demo Fallback)
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400">
                Primary persistent storage for SOC alerts, SHAP explanations & triage priority logs
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchStatus}
              disabled={loading}
              title="Refresh connection status"
              className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/10 transition-colors disabled:opacity-50"
            >
              <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            </button>
            <button
              onClick={onClose}
              title="Close modal (Esc)"
              className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Tab Selector */}
        <div className="flex border-b border-white/8 px-6 bg-black/20 gap-4 text-xs font-medium">
          <button
            onClick={() => setActiveTab('health')}
            className={`py-3 border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'health'
                ? 'border-cyan-400 text-cyan-300 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Server size={14} />
            Cluster & Index Health
          </button>
          <button
            onClick={() => setActiveTab('sample')}
            className={`py-3 border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'sample'
                ? 'border-cyan-400 text-cyan-300 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode2 size={14} />
            Live Indexed Document
          </button>
          <button
            onClick={() => setActiveTab('queries')}
            className={`py-3 border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'queries'
                ? 'border-cyan-400 text-cyan-300 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal size={14} />
            Direct API & Query Access
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {activeTab === 'health' && (
            <div className="space-y-5">
              {/* Metric Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/8">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Cluster Name</span>
                  <div className="text-sm font-semibold text-white mt-1 truncate">
                    {status?.cluster_name ?? 'docker-cluster'}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/8">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Elasticsearch Version</span>
                  <div className="text-sm font-semibold text-cyan-400 mt-1">
                    {status?.version ? `v${status.version}` : '—'}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/8">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Target Index</span>
                  <div className="text-sm font-semibold text-amber-400 mt-1 truncate">
                    {status?.index ?? '—'}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/8">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Indexed Alerts</span>
                  <div className="text-sm font-semibold text-emerald-400 mt-1 font-mono">
                    {status?.docs_count != null ? `${status.docs_count} docs` : '—'}
                  </div>
                </div>
              </div>

              {/* Status details card */}
              <div className="p-4 rounded-xl bg-white/[0.02] border border-white/8 space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Layers size={14} className="text-cyan-400" />
                  Database Connection Info
                </h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="flex justify-between py-1.5 border-b border-white/5">
                    <span className="text-slate-400">Cluster URL:</span>
                    <span className="font-mono text-slate-200">{status?.url || 'http://localhost:9200'}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-white/5">
                    <span className="text-slate-400">Index Status:</span>
                    <span className="font-mono text-emerald-400">
                      {status?.index_exists ? 'Active & Initialized' : 'Not initialized'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-white/5">
                    <span className="text-slate-400">Storage Engine:</span>
                    <span className="text-slate-200">Distributed Lucene Store</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-white/5">
                    <span className="text-slate-400">Fallback Protection:</span>
                    <span className="text-emerald-400">Automatic demo_alerts.json fallback</span>
                  </div>
                </div>

                {status?.error && (
                  <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
                    <AlertTriangle size={15} className="shrink-0" />
                    <span>{status.error}</span>
                  </div>
                )}
              </div>

              {/* SOC Use Case Explanations */}
              <div className="p-4 rounded-xl bg-gradient-to-br from-cyan-950/20 to-emerald-950/20 border border-cyan-500/20 space-y-2">
                <h4 className="text-xs font-bold text-cyan-300 flex items-center gap-1.5">
                  <CheckCircle2 size={14} className="text-emerald-400" />
                  What is the Database used for right now?
                </h4>
                <ul className="text-xs text-slate-300 space-y-1.5 pl-4 list-disc marker:text-cyan-400">
                  <li>
                    <strong className="text-white">Incident Queue & Search:</strong> Powers the <strong>Incident Triage (/alerts)</strong> queue with fast queries by IP, attack family, protocol, and assigned tier.
                  </li>
                  <li>
                    <strong className="text-white">Audit Trail & Forensics:</strong> Retains all raw flow features, SHAP contribution scores, and autoencoder reconstruction errors for post-incident investigation.
                  </li>
                  <li>
                    <strong className="text-white">Live Alert Replay:</strong> Allows an analyst to fetch any past alert by its ID and re-execute it through the dual-model pipeline.
                  </li>
                  <li>
                    <strong className="text-white">Automated Triage Ingestion:</strong> Evaluated alerts from <code className="text-cyan-300 font-mono">POST /api/detect</code> are stored automatically in real time.
                  </li>
                </ul>
              </div>
            </div>
          )}

          {activeTab === 'sample' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400">
                  Sample Alert Stored in <span className="font-mono text-cyan-400">aegis-alerts</span> index
                </span>
                {sampleAlert && (
                  <button
                    onClick={() => copyToClipboard(JSON.stringify(sampleAlert, null, 2), 'sample')}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono bg-white/5 hover:bg-white/10 text-slate-300 transition-colors border border-white/10"
                  >
                    {copied === 'sample' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    {copied === 'sample' ? 'Copied' : 'Copy JSON'}
                  </button>
                )}
              </div>

              {sampleAlert ? (
                <div className="relative rounded-xl border border-white/10 bg-black/60 p-4 font-mono text-[11px] text-emerald-300 overflow-x-auto max-h-[380px]">
                  <pre>{JSON.stringify(sampleAlert, null, 2)}</pre>
                </div>
              ) : (
                <div className="p-8 text-center text-slate-400 text-xs">
                  No sample alert retrieved from database.
                </div>
              )}
            </div>
          )}

          {activeTab === 'queries' && (
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                    <Terminal size={14} className="text-cyan-400" />
                    Query Elasticsearch directly via cURL
                  </span>
                  <button
                    onClick={() => copyToClipboard(curlQuery, 'curl')}
                    className="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10"
                  >
                    {copied === 'curl' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    {copied === 'curl' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div className="p-3 rounded-xl bg-black/60 border border-white/10 font-mono text-xs text-slate-200 overflow-x-auto">
                  <pre className="text-emerald-400">{curlQuery}</pre>
                </div>
              </div>

              <div className="space-y-2 pt-2">
                <span className="text-xs font-semibold text-slate-300">Quick Browser Endpoints</span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <a
                    href="http://localhost:9200/aegis-alerts/_search?pretty"
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-between p-3 rounded-xl bg-white/[0.03] hover:bg-white/[0.08] border border-white/8 text-slate-300 hover:text-white transition-all group"
                  >
                    <div>
                      <div className="font-semibold text-cyan-400">Elasticsearch Raw Search</div>
                      <div className="text-[11px] text-slate-500 font-mono">http://localhost:9200/aegis-alerts/_search</div>
                    </div>
                    <ExternalLink size={14} className="group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                  </a>

                  <a
                    href="http://localhost:8000/api/alerts?limit=50"
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-between p-3 rounded-xl bg-white/[0.03] hover:bg-white/[0.08] border border-white/8 text-slate-300 hover:text-white transition-all group"
                  >
                    <div>
                      <div className="font-semibold text-emerald-400">FastAPI Alerts API</div>
                      <div className="text-[11px] text-slate-500 font-mono">http://localhost:8000/api/alerts</div>
                    </div>
                    <ExternalLink size={14} className="group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                  </a>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-white/8 bg-black/20 flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>Index: <strong className="text-white">aegis-alerts</strong></span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-xl bg-white/10 hover:bg-white/20 text-white font-medium transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
