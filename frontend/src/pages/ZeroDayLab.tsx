import { useEffect, useState } from 'react'
import { 
  Radar, 
  Play, 
  Flame, 
  Globe, 
  Lock, 
  BarChart3, 
  Zap
} from 'lucide-react'
import { detectFlow, getSchema, type DetectResult } from '../api'
import { ScrollSection } from '../components/ScrollSection'

const PRESET_DESCRIPTIONS: Record<string, { label: string; desc: string; icon: typeof Globe }> = {
  benign_web: {
    label: 'Benign Web Session',
    desc: 'Normal HTTP traffic with standard payload sizes and zero error flags.',
    icon: Globe,
  },
  known_dos: {
    label: 'Known SYN Flood (DoS)',
    desc: 'Classic Neptune/SYN flood against an internal port with 100% serror rate.',
    icon: Flame,
  },
  probe_scan: {
    label: 'Port Sweep (Probe)',
    desc: 'Rapid ICMP echo sweep probing multiple destination subnets.',
    icon: Radar,
  },
  zero_day_like: {
    label: 'Held-Out Zero-Day',
    desc: 'Novel TFTP anomaly with high reconstruction error and weak classifier confidence.',
    icon: Zap,
  },
}

const CATEGORIES = [
  { id: 'network', label: 'Network & Protocol', icon: Globe },
  { id: 'host', label: 'Host & Auth Signals', icon: Lock },
  { id: 'traffic', label: 'Traffic & Error Dynamics', icon: BarChart3 },
]

export default function ZeroDayLab() {
  const [presets, setPresets] = useState<Record<string, Record<string, string | number>>>({})
  const [form, setForm] = useState<Record<string, string | number>>({})
  const [activeCategory, setActiveCategory] = useState<'network' | 'host' | 'traffic'>('network')
  const [result, setResult] = useState<DetectResult | null>(null)
  const [activeExplainTab, setActiveExplainTab] = useState<'shap' | 'anomaly'>('anomaly')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    getSchema().then((s) => {
      setPresets(s.presets)
      setForm(s.presets.benign_web)
      // Score initial preset
      detectFlow(s.presets.benign_web).then(setResult).catch(() => {})
    })
  }, [])

  async function runDetection() {
    setBusy(true)
    setError('')
    try {
      const res = await detectFlow(form)
      setResult(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Detection failed')
    } finally {
      setBusy(false)
    }
  }

  function applyPreset(key: string) {
    if (presets[key]) {
      setForm(presets[key])
      detectFlow(presets[key]).then(setResult).catch(() => {})
    }
  }

  // Feature field categorisation
  const categoryKeys: Record<string, string[]> = {
    network: ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent'],
    host: ['hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login'],
    traffic: ['count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'],
  }

  const isZeroDay = result?.is_zero_day ?? false
  const anomalyRatio = result?.anomaly_ratio ?? 0
  const reconThreshold = result?.threshold ?? 0.2471

  return (
    <div className="space-y-8 animate-fade-in max-w-7xl mx-auto pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/8 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400">Problem 1 · Live Detection Studio</span>
            <span className="text-slate-600">·</span>
            <span className="text-xs font-mono text-slate-400">Autoencoder + XGBoost Cockpit</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">Zero-Day Simulation Studio</h1>
        </div>

        <div className="glass-pill px-3 py-1.5 rounded-xl text-xs font-mono text-slate-300">
          Baseline Anomaly Threshold: <span className="text-cyan-400 font-bold">{reconThreshold.toFixed(4)}</span>
        </div>
      </div>

      {/* Preset Scenario Cards */}
      <ScrollSection delay={40}>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {Object.entries(PRESET_DESCRIPTIONS).map(([key, meta]) => {
            const Icon = meta.icon
            const isSelected = JSON.stringify(form) === JSON.stringify(presets[key])

            return (
              <button
                key={key}
                onClick={() => applyPreset(key)}
                className={`p-4 rounded-2xl text-left transition-all border ${
                  isSelected
                    ? 'bg-cyan-500/10 border-cyan-400/50 shadow-lg shadow-cyan-500/10'
                    : 'glass-card border-white/5 hover:border-white/20'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className={`h-8 w-8 rounded-xl grid place-items-center ${isSelected ? 'bg-cyan-500 text-slate-950' : 'bg-white/5 text-slate-300'}`}>
                    <Icon size={16} />
                  </div>
                  {isSelected && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-400/20 text-cyan-300 font-medium">
                      ACTIVE
                    </span>
                  )}
                </div>
                <h3 className="text-xs font-bold text-white mb-1">{meta.label}</h3>
                <p className="text-[11px] text-slate-400 leading-snug line-clamp-2">{meta.desc}</p>
              </button>
            )
          })}
        </div>
      </ScrollSection>

      {/* Studio Workbench: Feature Editor on Left + Live Cockpit on Right */}
      <ScrollSection delay={100}>
        <div className="grid lg:grid-cols-12 gap-6 items-start">
        {/* Left: Tabbed Flow Parameter Editor */}
        <div className="lg:col-span-7 glass-card p-6 space-y-6 border border-white/10">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div>
              <h2 className="text-base font-semibold text-white">Flow Feature Vector</h2>
              <p className="text-xs text-slate-400">Modify connection attributes to test the dual-model novelty boundary.</p>
            </div>

            <button
              onClick={runDetection}
              disabled={busy}
              className="py-2 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-teal-500 text-slate-950 font-bold text-xs hover:from-cyan-400 hover:to-teal-400 transition-all flex items-center gap-1.5 shadow-md shadow-cyan-500/20 disabled:opacity-50"
            >
              <Play size={14} className="fill-current" />
              <span>{busy ? 'Evaluating...' : 'Run Detector'}</span>
            </button>
          </div>

          {/* Category Tabs */}
          <div className="flex items-center gap-2 border-b border-white/5 pb-2">
            {CATEGORIES.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveCategory(id as any)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-medium transition-all ${
                  activeCategory === id
                    ? 'bg-white/15 text-white border border-white/20'
                    : 'text-slate-400 hover:text-white hover:bg-white/5'
                }`}
              >
                <Icon size={14} />
                <span>{label}</span>
              </button>
            ))}
          </div>

          {/* Form Inputs Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 max-h-[460px] overflow-y-auto pr-1">
            {categoryKeys[activeCategory]?.map((key) => (
              <div key={key} className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400 block truncate" title={key}>
                  {key}
                </label>
                <input
                  type="text"
                  value={form[key] ?? ''}
                  onChange={(e) => {
                    const raw = e.target.value
                    setForm((prev) => ({
                      ...prev,
                      [key]: Number.isNaN(Number(raw)) || raw === '' ? raw : Number(raw),
                    }))
                  }}
                  className="w-full bg-slate-900/80 border border-white/10 rounded-lg px-2.5 py-1.5 font-mono text-xs text-white focus:outline-none focus:border-cyan-400/50"
                />
              </div>
            ))}
          </div>

          {error && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/25 text-rose-300 text-xs">
              {error}
            </div>
          )}
        </div>

        {/* Right: Live Decision Cockpit */}
        <div className="lg:col-span-5 space-y-5">
          {/* Main Decision Badge Card */}
          <div className="glass-card p-6 border border-white/15 space-y-5">
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Hybrid Decision Output
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                Leave-Family-Out Gate
              </span>
            </div>

            {result ? (
              <div className="space-y-5">
                {/* Decision Headline */}
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-2xl sm:text-3xl font-extrabold text-white capitalize tracking-tight">
                      {result.predicted.replace('_', ' ')}
                    </div>
                    <div className="text-xs text-slate-400 mt-1 font-mono">
                      Known Family: <span className="text-slate-200 capitalize font-medium">{result.known_class}</span> ({(result.confidence * 100).toFixed(1)}% conf)
                    </div>
                  </div>

                  {isZeroDay ? (
                    <span className="px-3 py-1 rounded-full text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 glow-emerald">
                      NOVEL THREAT
                    </span>
                  ) : (
                    <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      KNOWN SIGNATURE
                    </span>
                  )}
                </div>

                {/* Reconstruction Anomaly Meter */}
                <div className="p-4 rounded-xl bg-slate-900/60 border border-white/5 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400 font-medium">Reconstruction Error vs Threshold</span>
                    <span className="font-mono text-cyan-300 font-bold">
                      {result.reconstruction_error.toFixed(4)} / {reconThreshold.toFixed(4)}
                    </span>
                  </div>
                  <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        result.reconstruction_error > reconThreshold ? 'bg-cyan-400' : 'bg-emerald-400'
                      }`}
                      style={{
                        width: `${Math.min((result.reconstruction_error / (reconThreshold * 2)) * 100, 100)}%`,
                      }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-500">
                    <span>Baseline Normal</span>
                    <span>{anomalyRatio.toFixed(2)}× Threshold Ratio</span>
                  </div>
                </div>

                {/* Telemetry Grid */}
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-2.5 rounded-lg bg-black/25">
                    <span className="text-slate-500 text-[10px] uppercase font-bold">Composite Priority</span>
                    <div className="text-base font-bold font-mono text-emerald-400 mt-0.5">
                      {result.priority.toFixed(3)}
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-black/25">
                    <span className="text-slate-500 text-[10px] uppercase font-bold">Assigned Tier</span>
                    <div className="text-base font-bold text-white capitalize mt-0.5">
                      {result.tier.replace('_', ' ')}
                    </div>
                  </div>
                </div>

                {/* Rationale String */}
                <div className="p-3 rounded-xl bg-slate-900/80 border border-white/5 text-xs text-slate-300 leading-relaxed">
                  {result.rationale}
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-slate-500 text-xs">
                Select a preset or click Run Detector to evaluate.
              </div>
            )}
          </div>

          {/* Explainability Card: SHAP vs Anomaly Attribution */}
          {result && (
            <div className="glass-card p-6 border border-white/10 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Feature Explainability
                </span>

                <div className="inline-flex p-0.5 rounded-lg bg-black/30 text-[11px]">
                  <button
                    onClick={() => setActiveExplainTab('anomaly')}
                    className={`px-2.5 py-1 rounded-md transition-all ${
                      activeExplainTab === 'anomaly' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Anomaly Attribution
                  </button>
                  <button
                    onClick={() => setActiveExplainTab('shap')}
                    className={`px-2.5 py-1 rounded-md transition-all ${
                      activeExplainTab === 'shap' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    SHAP Impact
                  </button>
                </div>
              </div>

              {activeExplainTab === 'anomaly' ? (
                <div className="space-y-2">
                  <p className="text-[11px] text-slate-400">
                    Autoencoder squared reconstruction error shares (why this flow looks abnormal):
                  </p>
                  <div className="space-y-1.5">
                    {result.anomaly_features?.slice(0, 5).map((f) => (
                      <div key={f.feature} className="p-2 rounded-lg bg-slate-900/50 text-xs space-y-1">
                        <div className="flex justify-between font-mono text-[11px]">
                          <span className="text-slate-300 font-semibold">{f.feature}</span>
                          <span className="text-cyan-400 font-bold">{(f.error_share * 100).toFixed(1)}% share</span>
                        </div>
                        <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                          <span>Input: {f.value.toFixed(2)}</span>
                          <span>Reconstructed: {f.reconstructed.toFixed(2)}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <p className="text-[11px] text-slate-400">
                    SHAP TreeExplainer contributions for the XGBoost known-family classifier:
                  </p>
                  <div className="space-y-1.5">
                    {result.top_features?.slice(0, 5).map((f) => (
                      <div key={f.feature} className="flex items-center justify-between p-2 rounded-lg bg-slate-900/50 text-xs font-mono">
                        <span className="text-slate-300 truncate max-w-[150px]">{f.feature}</span>
                        <span className={f.impact >= 0 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                          {f.impact >= 0 ? '+' : ''}{f.impact.toFixed(3)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      </ScrollSection>
    </div>
  )
}
