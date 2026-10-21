import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { 
  ShieldAlert, 
  Radar, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  Gauge, 
  ChevronRight, 
  Info,
  Layers,
  Sparkles,
  Target,
  FileCheck2,
  TrendingDown,
  Cpu
} from 'lucide-react'
import { getSummary, type Summary } from '../api'
import { ScrollSection } from '../components/ScrollSection'
import { useTheme } from '../context/ThemeContext'

const FAMILY_COLORS: Record<string, string> = {
  normal: '#10b981',   // emerald
  dos: '#f43f5e',      // crimson rose
  probe: '#f59e0b',    // warm amber
  r2l: '#8b5cf6',      // violet
  u2r: '#ec4899',      // fuchsia
  zero_day: '#06b6d4', // cyan
}

function fmtPercent(n?: number | null, digits = 1) {
  if (n == null || Number.isNaN(n)) return '—'
  return `${(n * 100).toFixed(digits)}%`
}

export default function Overview() {
  const { theme } = useTheme()
  const [data, setData] = useState<Summary | null>(null)
  const [error, setError] = useState('')
  const [activeView, setActiveView] = useState<'soc' | 'validation'>('soc')

  useEffect(() => {
    getSummary().then(setData).catch((e) => setError(e.message))
  }, [])

  if (error) {
    return (
      <div className="glass-card p-8 max-w-xl mx-auto text-center space-y-4">
        <div className="h-12 w-12 rounded-2xl bg-rose-500/10 text-rose-400 grid place-items-center mx-auto">
          <AlertTriangle size={24} />
        </div>
        <h2 className="text-xl font-bold text-white">Backend Connection Error</h2>
        <p className="text-sm text-slate-400">{error}. Ensure the FastAPI server is running on port 8000.</p>
        <code className="block bg-black/40 p-3 rounded-xl text-xs font-mono text-slate-300">
          cd backend && python -m uvicorn app.main:app --reload --port 8000
        </code>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-3 text-slate-400">
        <div className="h-8 w-8 rounded-full border-2 border-emerald-400 border-t-transparent animate-spin" />
        <span className="text-sm font-medium">Synchronizing Threat Operations...</span>
      </div>
    )
  }

  if (!data.ready) {
    return (
      <div className="glass-card p-8 max-w-xl mx-auto text-center space-y-4">
        <div className="h-12 w-12 rounded-2xl bg-amber-500/10 text-amber-400 grid place-items-center mx-auto">
          <Clock size={24} />
        </div>
        <h2 className="text-xl font-bold text-white">Model Artifacts Not Found</h2>
        <p className="text-sm text-slate-400">{data.message}</p>
        <code className="block bg-black/40 p-3 rounded-xl text-xs font-mono text-slate-300">
          cd backend && python -m app.ml.train
        </code>
      </div>
    )
  }

  const p3 = data.problem3
  const p3w = p3?.workload
  const p3t = p3?.threat_preservation

  const pieData = Object.entries(data.alert_mix || {}).map(([name, value]) => ({
    name: name.replace('_', ' ').toUpperCase(),
    rawName: name,
    value,
    color: FAMILY_COLORS[name] || '#94a3b8',
  }))

  const heldOutLabels = data.held_out_labels || [
    'apache2', 'httptunnel', 'mailbomb', 'mscan', 'named',
    'processtable', 'ps', 'saint', 'sendmail', 'snmpguess',
    'sqlattack', 'udpstorm', 'worm', 'xlock', 'xterm'
  ]

  return (
    <div className="space-y-8 animate-fade-in max-w-7xl mx-auto pb-12">
      {/* Top Banner & Mode Toggle */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/8 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            {activeView === 'soc' ? (
              <>
                <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  Threat Operations Center
                </span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-slate-400">{data.dataset} Telemetry</span>
              </>
            ) : (
              <>
                <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                  Academic Benchmark Evaluation
                </span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-cyan-300/80">NSL-KDD Test Split (Dai et al. Protocol)</span>
              </>
            )}
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            {activeView === 'soc' ? 'Active Incident Posture' : 'Benchmark Performance & Generalization'}
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            {activeView === 'soc'
              ? 'Operational view: autonomous tiering triage, analyst workload fatigue reduction, and high-priority queues.'
              : 'Research view: leave-family-out isolation protocol, in-sample vs out-of-sample generalization gap, and confusion matrix.'}
          </p>
        </div>

        {/* Mode Toggle: SOC Operations vs Academic Benchmark */}
        <div className="inline-flex p-1 rounded-xl glass-panel border border-white/10 self-start md:self-auto shrink-0 shadow-lg shadow-black/20">
          <button
            onClick={() => setActiveView('soc')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-2 ${
              activeView === 'soc'
                ? 'bg-emerald-500/20 text-emerald-300 shadow-sm border border-emerald-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <ShieldAlert size={14} className={activeView === 'soc' ? 'text-emerald-400' : 'text-slate-500'} />
            SOC Operations Mode
          </button>
          <button
            onClick={() => setActiveView('validation')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-2 ${
              activeView === 'validation'
                ? 'bg-cyan-500/20 text-cyan-300 shadow-sm border border-cyan-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Cpu size={14} className={activeView === 'validation' ? 'text-cyan-400' : 'text-slate-500'} />
            Academic Benchmark Mode
          </button>
        </div>
      </div>

      {/* KPI Ribbon: Changes Dynamically Based On Mode */}
      <ScrollSection delay={40}>
        {activeView === 'soc' ? (
          /* SOC Operations Ribbon */
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 animate-fade-in">
            {/* KPI 1 */}
            <div className="glass-card p-5 space-y-2 border border-white/10 hover:border-emerald-500/20 transition-all">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-medium uppercase tracking-wider">Detection Efficacy</span>
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-beacon" />
              </div>
              <div className="text-3xl font-bold font-mono text-white">
                {fmtPercent(data.kpis?.test_accuracy)}
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-white/5">
                <span>Attack Recall:</span>
                <span className="font-mono text-emerald-400 font-semibold">{fmtPercent(data.kpis?.test_recall)}</span>
              </div>
            </div>

            {/* KPI 2 */}
            <div className="glass-card p-5 space-y-2 border border-white/10 hover:border-emerald-500/20 transition-all">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-medium uppercase tracking-wider">Fatigue Reduction</span>
                <Gauge size={15} className="text-emerald-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-emerald-400">
                {fmtPercent(p3w?.auto_logged_share ?? data.kpis?.auto_logged_share)}
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-white/5">
                <span>Benchmark Workload Saved:</span>
                <span className="font-mono text-emerald-300 font-semibold">
                  {p3w?.tier_counts?.auto_log != null ? `${p3w.tier_counts.auto_log.toLocaleString()} / 22,544 Flows` : '10,746 / 22,544 Flows'}
                </span>
              </div>
            </div>

            {/* KPI 3 */}
            <div className="glass-card p-5 space-y-2 border border-white/10 hover:border-rose-500/20 transition-all">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-medium uppercase tracking-wider">Live Critical Queue</span>
                <ShieldAlert size={15} className="text-rose-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-rose-400">
                {data.kpis?.critical_tier_alerts != null ? `${data.kpis.critical_tier_alerts.toLocaleString()} Alerts` : '—'}
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-white/5">
                <span>Benchmark Target:</span>
                <span className="font-mono text-rose-300 font-semibold">
                  {p3w?.tier_counts?.critical?.toLocaleString() ?? '10,177'} flows · {fmtPercent(p3?.per_tier?.critical?.precision ?? 0.9371)} prec
                </span>
              </div>
            </div>

            {/* KPI 4 */}
            <div className="glass-card p-5 space-y-2 border border-white/10 hover:border-teal-500/20 transition-all">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-medium uppercase tracking-wider">Human Tiers Threat Capture</span>
                <CheckCircle2 size={15} className="text-teal-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-teal-300">
                {fmtPercent(p3t?.attacks_in_human_tiers ?? 0.854)}
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-white/5">
                <span>Zero-Days In Human Queue:</span>
                <span className="font-mono text-teal-400 font-semibold">{fmtPercent(p3t?.zero_days_in_human_tiers ?? 0.782)}</span>
              </div>
            </div>
          </div>
        ) : (
          /* Academic Benchmark Ribbon */
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 animate-fade-in">
            {/* KPI 1 */}
            <div className="glass-card p-5 space-y-2 border border-cyan-500/20 bg-cyan-950/10 hover:border-cyan-500/40 transition-all">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-medium uppercase tracking-wider text-cyan-300">Official Test Accuracy</span>
                <span className="h-2 w-2 rounded-full bg-cyan-400 animate-beacon" />
              </div>
              <div className="text-3xl font-bold font-mono text-cyan-400">
                {fmtPercent(data.kpis?.test_accuracy)}
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-white/5">
                <span>Validation In-Sample:</span>
                <span className="font-mono text-slate-300 font-semibold">{fmtPercent(data.kpis?.validation_accuracy ?? 0.9786)}</span>
              </div>
            </div>

            {/* KPI 2 */}
            <div className="glass-card p-5 space-y-2 border border-white/10 hover:border-emerald-500/20 transition-all">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-medium uppercase tracking-wider">Attack Recall & F1</span>
                <Target size={15} className="text-emerald-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-white">
                {fmtPercent(data.kpis?.test_recall)}
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-white/5">
                <span>Official Test F1:</span>
                <span className="font-mono text-emerald-400 font-semibold">{fmtPercent(data.kpis?.test_f1)}</span>
              </div>
            </div>

            {/* KPI 3 */}
            <div className="glass-card p-5 space-y-2 border border-white/10 hover:border-cyan-500/20 transition-all">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-medium uppercase tracking-wider">Zero-Day Screening</span>
                <Radar size={15} className="text-cyan-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-cyan-300">
                {fmtPercent(data.kpis?.zero_day_detection_rate)}
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-white/5">
                <span>Explicit Novel Flag Rate:</span>
                <span className="font-mono text-cyan-400 font-semibold">{fmtPercent(data.kpis?.novel_flag_rate)}</span>
              </div>
            </div>

            {/* KPI 4 */}
            <div className="glass-card p-5 space-y-2 border border-white/10 hover:border-violet-500/20 transition-all">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-medium uppercase tracking-wider">ROC-AUC Discriminability</span>
                <Sparkles size={15} className="text-violet-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-violet-300">
                {(data.kpis?.test_roc_auc ?? 0.9528).toFixed(3)}
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-white/5">
                <span>Attack Precision:</span>
                <span className="font-mono text-violet-300 font-semibold">{fmtPercent(data.kpis?.test_precision ?? 0.9315)}</span>
              </div>
            </div>
          </div>
        )}
      </ScrollSection>

      {/* Main Grid: Dynamically Switches Between SOC Triage & Academic Benchmarks */}
      {activeView === 'soc' ? (
        /* SOC MODE: Traffic Distribution & Triage Funnel */
        <ScrollSection delay={100}>
          <div className="grid lg:grid-cols-12 gap-6 animate-fade-in">
            {/* Left: Traffic Distribution Chart */}
            <div className="lg:col-span-6 glass-card p-6 space-y-5 border border-white/10 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <h2 className="text-base font-semibold text-white tracking-tight">Threat Classification Mix</h2>
                  <span className="text-[11px] font-mono text-slate-400">{(data.test_rows ?? 22544).toLocaleString()} Flows</span>
                </div>
                <p className="text-xs text-slate-400">Classified by the hybrid XGBoost + Autoencoder model.</p>
              </div>

              <div className="h-64 relative flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={65}
                      outerRadius={95}
                      paddingAngle={3}
                      dataKey="value"
                      stroke={theme === 'light' ? '#ffffff' : 'rgba(7, 11, 18, 0.8)'}
                      strokeWidth={2}
                    >
                      {pieData.map((entry) => (
                        <Cell key={entry.rawName} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: theme === 'light' ? 'rgba(255, 255, 255, 0.96)' : 'rgba(13, 20, 36, 0.95)',
                        borderColor: theme === 'light' ? 'rgba(203, 213, 225, 0.8)' : 'rgba(255, 255, 255, 0.15)',
                        borderRadius: '12px',
                        fontSize: '12px',
                        color: theme === 'light' ? '#0f172a' : '#f8fafc',
                        boxShadow: theme === 'light' ? '0 10px 25px -5px rgba(0,0,0,0.1)' : undefined,
                      }}
                      itemStyle={{ color: theme === 'light' ? '#0f172a' : '#f8fafc' }}
                      formatter={(val: any) => [`${Number(val || 0).toLocaleString()} flows`, 'Count']}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              {/* Legend Grid */}
              <div className="grid grid-cols-3 gap-2.5 pt-3 border-t border-white/5">
                {pieData.map((item) => (
                  <div key={item.rawName} className="p-2 rounded-lg bg-black/25 flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                    <div className="overflow-hidden">
                      <div className="text-[10px] font-semibold text-slate-300 truncate">{item.name}</div>
                      <div className="text-[11px] font-mono text-slate-400 font-medium">
                        {item.value.toLocaleString()}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: Problem 3 Triage Funnel */}
            <div className="lg:col-span-6 glass-card p-6 space-y-5 border border-white/10 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <h2 className="text-base font-semibold text-white tracking-tight">Autonomous Tiered Triage Funnel</h2>
                  <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    Offline Benchmark Evaluation
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Evaluated across {(data.test_rows ?? 22544).toLocaleString()} official test flows. Cutoffs frozen on validation true labels: Critical ≥ {data.prioritisation?.tier_cutoffs?.critical?.toFixed(3) ?? '0.590'}, Review ≥ {data.prioritisation?.tier_cutoffs?.review?.toFixed(3) ?? '0.136'}.
                </p>
              </div>

              <div className="space-y-3.5 my-auto">
                {/* Critical Tier */}
                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/25 space-y-2">
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="flex items-center gap-2 text-rose-300">
                      <span className="w-2 h-2 rounded-full bg-rose-400" />
                      CRITICAL TIER (Benchmark Capacity)
                    </span>
                    <span className="font-mono text-rose-300">{p3w?.tier_counts?.critical?.toLocaleString() ?? '10,177'} flows (45.1%)</span>
                  </div>
                  <div className="w-full bg-black/40 h-2 rounded-full overflow-hidden">
                    <div className="bg-rose-500 h-full rounded-full" style={{ width: `${(p3?.per_tier?.critical?.precision ?? 0.9371) * 100}%` }} />
                  </div>
                  <div className="flex justify-between text-[11px] text-slate-400">
                    <span>Contains 9,537 true attacks</span>
                    <span className="text-rose-400 font-medium">{fmtPercent(p3?.per_tier?.critical?.precision ?? 0.9371)} Tier Precision</span>
                  </div>
                </div>

                {/* Review Tier */}
                <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/25 space-y-2">
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="flex items-center gap-2 text-amber-300">
                      <span className="w-2 h-2 rounded-full bg-amber-400" />
                      REVIEW TIER (Analyst Queue + Unknown Asset Floor)
                    </span>
                    <span className="font-mono text-amber-300">{p3w?.tier_counts?.review?.toLocaleString() ?? '1,621'} flows (7.2%)</span>
                  </div>
                  <div className="w-full bg-black/40 h-2 rounded-full overflow-hidden">
                    <div className="bg-amber-400 h-full rounded-full" style={{ width: `${(p3?.per_tier?.review?.precision ?? 0.8797) * 100}%` }} />
                  </div>
                  <div className="flex justify-between text-[11px] text-slate-400">
                    <span>Contains 1,426 true attacks</span>
                    <span className="text-amber-400 font-medium">{fmtPercent(p3?.per_tier?.review?.precision ?? 0.8797)} Tier Precision</span>
                  </div>
                </div>

                {/* Auto-Log Tier */}
                <div className="p-4 rounded-xl bg-slate-800/40 border border-white/10 space-y-2">
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="flex items-center gap-2 text-slate-300">
                      <CheckCircle2 size={13} className="text-emerald-400" />
                      AUTO-LOGGED TIER (Automated Routine Archive)
                    </span>
                    <span className="font-mono text-slate-300">{p3w?.tier_counts?.auto_log?.toLocaleString() ?? '10,746'} flows (47.7%)</span>
                  </div>
                  <div className="w-full bg-black/40 h-2 rounded-full overflow-hidden">
                    <div className="bg-emerald-500 h-full rounded-full" style={{ width: '82.6%' }} />
                  </div>
                  <div className="flex justify-between text-[11px] text-slate-400">
                    <span>8,876 true benign flows auto-logged</span>
                    <span className="text-emerald-400 font-medium">Workload Saved: 47.7%</span>
                  </div>
                </div>
              </div>

              <div className="pt-2 flex items-center justify-between text-xs">
                <span className="text-slate-400">
                  Total human review share: <strong className="text-white font-mono">{fmtPercent(p3w?.human_review_workload ?? 0.523)}</strong>
                </span>
                <Link to="/alerts" className="text-emerald-400 hover:text-emerald-300 font-medium inline-flex items-center gap-1">
                  <span>View Incident Triage Queue</span>
                  <ChevronRight size={14} />
                </Link>
              </div>
            </div>
          </div>
        </ScrollSection>
      ) : (
        /* ACADEMIC BENCHMARK MODE: Validation vs Test Generalization & Confusion Matrix */
        <ScrollSection delay={100}>
          <div className="grid lg:grid-cols-12 gap-6 animate-fade-in">
            {/* Left: In-Sample vs Out-of-Sample Comparison */}
            <div className="lg:col-span-6 glass-card p-6 space-y-5 border border-white/10 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <h2 className="text-base font-semibold text-white tracking-tight flex items-center gap-2">
                    <Layers size={17} className="text-cyan-400" />
                    In-Sample Fit vs Out-of-Sample Generalization
                  </h2>
                  <span className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                    Distribution Shift
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Quantifying the performance delta when moving from known classes to genuinely unobserved attack families.
                </p>
              </div>

              <div className="space-y-4 my-auto">
                {/* Same-Distribution Validation */}
                <div className="p-4 rounded-xl bg-slate-900/60 border border-white/5 space-y-2.5">
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="text-emerald-400 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      Validation Split (Known Training Classes)
                    </span>
                    <span className="font-mono text-slate-300">{(data.validation_rows ?? 18896).toLocaleString()} flows</span>
                  </div>
                  
                  <div className="grid grid-cols-4 gap-2 pt-1 text-center font-mono">
                    <div className="bg-black/30 p-2 rounded-lg">
                      <div className="text-[10px] text-slate-500 uppercase">Accuracy</div>
                      <div className="text-xs font-bold text-white mt-0.5">{fmtPercent(data.kpis?.validation_accuracy ?? 0.9786)}</div>
                    </div>
                    <div className="bg-black/30 p-2 rounded-lg">
                      <div className="text-[10px] text-slate-500 uppercase">Precision</div>
                      <div className="text-xs font-bold text-white mt-0.5">{fmtPercent(data.kpis?.validation_precision ?? 0.9567)}</div>
                    </div>
                    <div className="bg-black/30 p-2 rounded-lg">
                      <div className="text-[10px] text-slate-500 uppercase">Recall</div>
                      <div className="text-xs font-bold text-emerald-400 mt-0.5">{fmtPercent(data.kpis?.validation_recall ?? 0.9993)}</div>
                    </div>
                    <div className="bg-black/30 p-2 rounded-lg">
                      <div className="text-[10px] text-slate-500 uppercase">F1-Score</div>
                      <div className="text-xs font-bold text-white mt-0.5">{fmtPercent(data.kpis?.validation_f1 ?? 0.9775)}</div>
                    </div>
                  </div>
                </div>

                {/* Official Test Split */}
                <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/25 space-y-2.5">
                  <div className="flex items-center justify-between text-xs font-semibold">
                    <span className="text-cyan-300 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-cyan-400" />
                      Official NSL-KDD Test (15 Unseen Zero-Day Families)
                    </span>
                    <span className="font-mono text-cyan-300">{(data.test_rows ?? 22544).toLocaleString()} flows</span>
                  </div>
                  
                  <div className="grid grid-cols-4 gap-2 pt-1 text-center font-mono">
                    <div className="bg-black/30 p-2 rounded-lg">
                      <div className="text-[10px] text-slate-500 uppercase">Accuracy</div>
                      <div className="text-xs font-bold text-cyan-400 mt-0.5">{fmtPercent(data.kpis?.test_accuracy ?? 0.8745)}</div>
                    </div>
                    <div className="bg-black/30 p-2 rounded-lg">
                      <div className="text-[10px] text-slate-500 uppercase">Precision</div>
                      <div className="text-xs font-bold text-white mt-0.5">{fmtPercent(data.kpis?.test_precision ?? 0.9315)}</div>
                    </div>
                    <div className="bg-black/30 p-2 rounded-lg">
                      <div className="text-[10px] text-slate-500 uppercase">Recall</div>
                      <div className="text-xs font-bold text-emerald-400 mt-0.5">{fmtPercent(data.kpis?.test_recall ?? 0.8413)}</div>
                    </div>
                    <div className="bg-black/30 p-2 rounded-lg">
                      <div className="text-[10px] text-slate-500 uppercase">F1-Score</div>
                      <div className="text-xs font-bold text-cyan-300 mt-0.5">{fmtPercent(data.kpis?.test_f1 ?? 0.8841)}</div>
                    </div>
                  </div>
                </div>

                {/* Generalization Note */}
                <div className="p-3 rounded-xl bg-black/40 border border-white/5 flex items-start gap-2.5 text-xs text-slate-400">
                  <TrendingDown size={16} className="text-amber-400 shrink-0 mt-0.5" />
                  <p className="leading-relaxed text-[11px]">
                    <strong className="text-slate-200">Scientific Honest Evaluation:</strong> Synthetic academic claims often report 99.9% by training and testing on identical attack patterns. Under genuine leave-family-out isolation, accuracy lands at a validated <strong className="text-white font-mono">87.45%</strong>, confirming real defense capability against unknown threats.
                  </p>
                </div>
              </div>

              <div className="pt-2 flex items-center justify-between text-xs border-t border-white/5">
                <span className="text-slate-400">
                  Unseen zero-day evaluation corpus: <strong className="text-cyan-400 font-mono">{(data.unseen_zero_day_rows ?? 3568).toLocaleString()} flows</strong>
                </span>
                <Link to="/model" className="text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1">
                  <span>View Full Model Governance Card</span>
                  <ChevronRight size={14} />
                </Link>
              </div>
            </div>

            {/* Right: Confusion Matrix & 3-Way Synergy */}
            <div className="lg:col-span-6 glass-card p-6 space-y-5 border border-white/10 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <h2 className="text-base font-semibold text-white tracking-tight flex items-center gap-2">
                    <FileCheck2 size={17} className="text-emerald-400" />
                    Official Test Split Confusion Matrix
                  </h2>
                  <span className="text-[11px] font-mono text-slate-400">22,544 Flows Evaluated</span>
                </div>
                <p className="text-xs text-slate-400">Binary ground truth vs hybrid detector predictions on the official test set.</p>
              </div>

              {/* 2x2 Confusion Matrix */}
              <div className="p-4 rounded-xl bg-black/40 border border-white/10 space-y-3">
                <div className="grid grid-cols-2 gap-3 text-center">
                  {/* True Negative */}
                  <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 space-y-1">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-400">
                      True Negative (Benign Passed)
                    </div>
                    <div className="text-2xl font-bold font-mono text-white">8,917</div>
                    <div className="text-[11px] text-slate-400 font-mono">91.8% Specificity</div>
                  </div>

                  {/* False Positive */}
                  <div className="p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/20 space-y-1">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-amber-400">
                      False Positive (False Alarms)
                    </div>
                    <div className="text-2xl font-bold font-mono text-white">794</div>
                    <div className="text-[11px] text-slate-400 font-mono">8.2% Benign FPR</div>
                  </div>

                  {/* False Negative */}
                  <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/20 space-y-1">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-rose-400">
                      False Negative (Missed Attacks)
                    </div>
                    <div className="text-2xl font-bold font-mono text-rose-300">2,036</div>
                    <div className="text-[11px] text-slate-400 font-mono">15.9% Miss Rate</div>
                  </div>

                  {/* True Positive */}
                  <div className="p-3.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 space-y-1">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-cyan-400">
                      True Positive (Attacks Detected)
                    </div>
                    <div className="text-2xl font-bold font-mono text-cyan-300">10,797</div>
                    <div className="text-[11px] text-slate-400 font-mono">84.1% Attack Recall</div>
                  </div>
                </div>
              </div>

              {/* 3-Way Pipeline Synergy Summary */}
              <div className="p-3.5 rounded-xl bg-slate-900/60 border border-white/5 space-y-2">
                <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                  <span>Hybrid Pipeline Synergy Advantage</span>
                  <span className="text-[10px] font-mono text-emerald-400">+2,461 Attacks Captured</span>
                </div>
                
                <div className="space-y-1.5 text-[11px] font-mono">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>XGBoost Classifier Alone:</span>
                    <span>4,497 Missed (65.0% Recall)</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-400">
                    <span>Autoencoder Anomaly Alone:</span>
                    <span>2,722 Missed (78.8% Recall)</span>
                  </div>
                  <div className="flex items-center justify-between text-emerald-300 font-bold bg-emerald-500/10 px-2 py-1 rounded">
                    <span>Hybrid Deployed Pipeline:</span>
                    <span>2,036 Missed (84.1% Recall) ✓</span>
                  </div>
                </div>
              </div>

              <div className="pt-2 flex items-center justify-between text-xs border-t border-white/5">
                <span className="text-slate-400">
                  Total test attacks: <strong className="text-white font-mono">12,833 flows</strong>
                </span>
                <Link to="/zero-day" className="text-emerald-400 hover:text-emerald-300 font-medium inline-flex items-center gap-1">
                  <span>Explore Zero-Day Studio</span>
                  <ChevronRight size={14} />
                </Link>
              </div>
            </div>
          </div>
        </ScrollSection>
      )}

      {/* Bottom Section: Changes Dynamically Based On Mode */}
      <ScrollSection delay={150}>
        {activeView === 'soc' ? (
          /* SOC Operations Mode: Auto-Logging Safety Audit */
          <div className="glass-card p-6 border border-white/10 space-y-4 animate-fade-in">
            <div className="flex items-center gap-2.5">
              <Info size={18} className="text-amber-400" />
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
                Auto-Logging Safety Audit (Honest Operational Findings)
              </h3>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              {p3?.limitation || (
                "On the NSL-KDD test set, 1,870 attacks (14.6% of attacks) and 779 held-out zero-days (21.8%) land in the auto_log tier without human review. A rigorous cross-tab audit confirms 100% of these auto-logged attacks had predicted_label='normal', high confidence (>91%), and low reconstruction error. This is an upstream detector limitation (attacks mimicking normal distributions), not a prioritization formula error."
              )}
            </p>

            <div className="grid sm:grid-cols-3 gap-3 pt-2">
              <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
                <span className="text-[10px] uppercase tracking-wide text-slate-500">Attacks in Human Tiers</span>
                <div className="text-lg font-bold font-mono text-emerald-400 mt-0.5">
                  {fmtPercent(p3t?.attacks_in_human_tiers ?? 0.854)} (10,963 / 12,833)
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
                <span className="text-[10px] uppercase tracking-wide text-slate-500">Zero-Days in Human Tiers</span>
                <div className="text-lg font-bold font-mono text-cyan-400 mt-0.5">
                  {fmtPercent(p3t?.zero_days_in_human_tiers ?? 0.782)} (2,789 / 3,568)
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
                <span className="text-[10px] uppercase tracking-wide text-slate-500">Composite vs Conf-Only P@K</span>
                <div className="text-lg font-bold font-mono text-white mt-0.5">
                  0.9316 vs 0.9313 (Ties)
                </div>
              </div>
            </div>
          </div>
        ) : (
          /* Academic Benchmark Mode: Leave-Family-Out Protocol & Governance */
          <div className="glass-card p-6 border border-white/10 space-y-4 animate-fade-in">
            <div className="flex items-center gap-2.5">
              <Radar size={18} className="text-cyan-400" />
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
                Dai et al. (2024) Leave-Family-Out Isolation Protocol & Research Governance
              </h3>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              To rigorously prevent data leakage, the 15 attack families below were strictly withheld from training and validation. 
              The reconstruction threshold (<code className="text-cyan-300 font-mono">0.2471</code>, 96th percentile of benign reconstruction error) 
              and novelty gate (<code className="text-cyan-300 font-mono">0.90</code>) were frozen on validation pseudo-zero-days (<code className="text-slate-300">back, nmap, warezclient</code>) with a benign FPR budget ≤ 5%.
            </p>

            {/* Held-out Labels Tags */}
            <div className="space-y-2 pt-1">
              <span className="text-[10px] uppercase tracking-wide text-slate-500 font-semibold block">
                15 Held-Out Zero-Day Attack Families:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {heldOutLabels.map((lbl) => (
                  <span
                    key={lbl}
                    className="px-2 py-0.5 rounded-md bg-cyan-950/40 text-cyan-300 border border-cyan-500/20 text-[11px] font-mono"
                  >
                    {lbl}
                  </span>
                ))}
              </div>
            </div>

            <div className="grid sm:grid-cols-3 gap-3 pt-2">
              <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
                <span className="text-[10px] uppercase tracking-wide text-slate-500">Zero-Day Detection Rate</span>
                <div className="text-lg font-bold font-mono text-cyan-400 mt-0.5">
                  {fmtPercent(data.kpis?.zero_day_detection_rate)} (2,725 / 3,568)
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
                <span className="text-[10px] uppercase tracking-wide text-slate-500">Explicit Novel Flag Rate</span>
                <div className="text-lg font-bold font-mono text-cyan-300 mt-0.5">
                  {fmtPercent(data.kpis?.novel_flag_rate)} (1,763 / 3,568)
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
                <span className="text-[10px] uppercase tracking-wide text-slate-500">Zero-Day Screening Precision</span>
                <div className="text-lg font-bold font-mono text-white mt-0.5">
                  0.516 (F1: 0.505)
                </div>
              </div>
            </div>
          </div>
        )}
      </ScrollSection>
    </div>
  )
}
