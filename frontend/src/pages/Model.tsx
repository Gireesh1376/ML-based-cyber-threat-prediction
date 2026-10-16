import { useEffect, useState } from 'react'
import { Radar } from 'lucide-react'
import { getMetrics } from '../api'
import { ScrollSection } from '../components/ScrollSection'

export default function Model() {
  const [metrics, setMetrics] = useState<Record<string, any> | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getMetrics().then(setMetrics).catch((e) => setError(e.message))
  }, [])

  if (error) {
    return (
      <div className="glass-card p-6 max-w-lg mx-auto text-center space-y-3">
        <h2 className="text-lg font-bold text-rose-400">Error Loading Model Metrics</h2>
        <p className="text-xs text-slate-400">{error}</p>
      </div>
    )
  }

  if (!metrics) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-3 text-slate-400">
        <div className="h-8 w-8 rounded-full border-2 border-emerald-400 border-t-transparent animate-spin" />
        <span className="text-sm font-medium">Loading Model Intelligence Card...</span>
      </div>
    )
  }

  const val = metrics.validation_binary || {}
  const test = metrics.official_test_binary || {}

  return (
    <div className="space-y-8 animate-fade-in max-w-7xl mx-auto pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/8 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">Pipeline Governance</span>
            <span className="text-slate-600">·</span>
            <span className="text-xs font-mono text-slate-400">Dual-Model Artifact Card</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">Model Intelligence & Validation</h1>
        </div>

        <div className="glass-pill px-3 py-1.5 rounded-xl text-xs font-mono text-slate-300">
          Architecture: <span className="text-emerald-400 font-semibold">{metrics.architecture || 'Autoencoder + XGBoost Hybrid'}</span>
        </div>
      </div>

      {/* Primary KPI Compare: Test vs Validation */}
      <ScrollSection delay={40}>
        <div className="grid md:grid-cols-2 gap-6">
          {/* Official Test Split */}
          <div className="glass-card p-6 space-y-4 border border-white/10">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div>
                <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Official NSL-KDD Test Split</span>
                <h3 className="text-lg font-bold text-white mt-0.5">Headline Test Performance</h3>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                {(metrics.test_rows || 22544).toLocaleString()} Flows
              </span>
            </div>

            <MetricGrid data={test} />
          </div>

          {/* Validation Split */}
          <div className="glass-card p-6 space-y-4 border border-white/10">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div>
                <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Same-Distribution Validation</span>
                <h3 className="text-lg font-bold text-white mt-0.5">Validation Split — Known Classes</h3>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {(metrics.validation_rows || 18896).toLocaleString()} Flows
              </span>
            </div>

            <MetricGrid data={val} />
          </div>
        </div>
      </ScrollSection>

      {/* Three-Way Detector Comparison */}
      <ScrollSection delay={100}>
        <div className="glass-card p-6 border border-white/10 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-white">Three-Way Pipeline Comparison</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Demonstrating the empirical advantage of pairing the autoencoder with the XGBoost classifier.
              </p>
            </div>
            <span className="text-xs font-mono text-slate-500 hidden sm:inline">12,833 Official Test Attacks</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0d1424] text-slate-400 border-b border-white/10">
                <tr>
                  <th className="py-2.5 px-3">Detector Configuration</th>
                  <th className="py-2.5 px-3">Attack Precision</th>
                  <th className="py-2.5 px-3">Attack Recall</th>
                  <th className="py-2.5 px-3">Attack F1</th>
                  <th className="py-2.5 px-3">Benign FPR</th>
                  <th className="py-2.5 px-3">Missed Attacks</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 font-mono">
                <tr className="hover:bg-white/5">
                  <td className="py-2.5 px-3 font-sans font-semibold text-slate-300">Classifier Only (XGBoost)</td>
                  <td className="py-2.5 px-3 text-emerald-400">96.9%</td>
                  <td className="py-2.5 px-3 text-slate-300">65.0%</td>
                  <td className="py-2.5 px-3 text-slate-300">0.778</td>
                  <td className="py-2.5 px-3 text-emerald-400">2.78%</td>
                  <td className="py-2.5 px-3 text-rose-400">4,497</td>
                </tr>
                <tr className="hover:bg-white/5">
                  <td className="py-2.5 px-3 font-sans font-semibold text-slate-300">Anomaly Only (Autoencoder)</td>
                  <td className="py-2.5 px-3 text-slate-300">93.4%</td>
                  <td className="py-2.5 px-3 text-slate-300">78.8%</td>
                  <td className="py-2.5 px-3 text-slate-300">0.855</td>
                  <td className="py-2.5 px-3 text-slate-400">7.41%</td>
                  <td className="py-2.5 px-3 text-slate-300">2,722</td>
                </tr>
                <tr className="bg-emerald-500/10 hover:bg-emerald-500/15 font-bold">
                  <td className="py-2.5 px-3 font-sans text-emerald-300 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    Hybrid Pipeline (Deployed)
                  </td>
                  <td className="py-2.5 px-3 text-slate-200">93.1%</td>
                  <td className="py-2.5 px-3 text-emerald-300">84.1%</td>
                  <td className="py-2.5 px-3 text-emerald-300">0.884</td>
                  <td className="py-2.5 px-3 text-slate-400">8.18%</td>
                  <td className="py-2.5 px-3 text-emerald-400 font-bold">2,036</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </ScrollSection>

      {/* Zero-Day Protocol Card */}
      <ScrollSection delay={150}>
        <div className="glass-card p-6 border border-white/10 space-y-4">
          <div className="flex items-center gap-2">
            <Radar size={18} className="text-cyan-400" />
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
              Zero-Day Hold-Out Protocol & Governance
            </h3>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            The 15 attack families in <code className="text-cyan-300">ZERO_DAY_LABELS</code> were excluded entirely from training.
            The novelty gate (<code className="text-slate-200">0.90</code>) and reconstruction quantile (<code className="text-slate-200">0.96</code>)
            were tuned on validation pseudo-zero-days (<code className="text-slate-200">back, nmap, warezclient</code>) with a false-positive budget ≤ 5%.
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 pt-2">
            <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">Held-Out Rows</span>
              <div className="text-xl font-bold font-mono text-white">3,568</div>
              <span className="text-[10px] text-slate-500">15 Attack Families</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">Held-out flows detected as non-normal</span>
              <div className="text-xl font-bold font-mono text-cyan-400">76.37%</div>
              <span className="text-[10px] text-slate-500">2,725 / 3,568</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">ZERO-DAY PRECISION</span>
              <div className="text-xl font-bold font-mono text-cyan-400">51.59%</div>
              <span className="text-[10px] text-slate-500">F1: 0.505</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">ZERO-DAY RECALL</span>
              <div className="text-xl font-bold font-mono text-cyan-400">49.41%</div>
              <span className="text-[10px] text-slate-500">1,763 / 3,568</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">ZERO-DAY FPR</span>
              <div className="text-xl font-bold font-mono text-cyan-400">8.72%</div>
              <span className="text-[10px] text-slate-500">1,654 / 18,976 non-zero-day flows</span>
            </div>
          </div>
        </div>
      </ScrollSection>
    </div>
  )
}

function MetricGrid({ data }: { data: Record<string, number> }) {
  const items = [
    { label: 'Accuracy', value: data.accuracy },
    { label: 'Precision', value: data.precision },
    { label: 'Recall', value: data.recall },
    { label: 'F1 Score', value: data.f1 },
    { label: 'ROC-AUC', value: data.roc_auc },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center">
      {items.map((item) => (
        <div key={item.label} className="p-3 rounded-xl bg-slate-900/60 border border-white/5">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">{item.label}</div>
          <div className="text-base font-bold font-mono text-white mt-1">
            {item.value != null ? `${(item.value * 100).toFixed(2)}%` : '—'}
          </div>
        </div>
      ))}
    </div>
  )
}
