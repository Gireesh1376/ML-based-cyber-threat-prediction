import { useEffect, useMemo, useState } from 'react'
import { 
  Search, 
  ShieldCheck, 
  AlertTriangle, 
  X, 
  RotateCw, 
  ArrowUpRight, 
  CheckCircle2,
  Database
} from 'lucide-react'
import { getAlerts, type AlertItem, type AlertsResponse } from '../api'
import { ScrollSection } from '../components/ScrollSection'

const TIER_CONFIG: Record<string, { label: string; badgeClass: string; barColor: string }> = {
  critical: { 
    label: 'Critical', 
    badgeClass: 'bg-rose-500/15 text-rose-300 border border-rose-500/30', 
    barColor: '#f43f5e' 
  },
  review: { 
    label: 'Review', 
    badgeClass: 'bg-amber-500/15 text-amber-300 border border-amber-500/30', 
    barColor: '#f59e0b' 
  },
  auto_log: { 
    label: 'Auto-Logged', 
    badgeClass: 'bg-slate-800/80 text-slate-400 border border-white/10', 
    barColor: '#64748b' 
  },
}

export default function Alerts() {
  const [data, setData] = useState<AlertsResponse | null>(null)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [selectedTier, setSelectedTier] = useState<string>('')
  const [onlyZeroDay, setOnlyZeroDay] = useState(false)
  const [activeAlert, setActiveAlert] = useState<AlertItem | null>(null)
  const [replaying, setReplaying] = useState(false)
  const [replayResult, setReplayResult] = useState<string | null>(null)

  useEffect(() => {
    getAlerts()
      .then((res) => {
        setData(res)
        if (res.items.length > 0) {
          // Default select the first item on larger displays
          setActiveAlert(res.items[0])
        }
      })
      .catch((e) => setError(e.message))
  }, [])

  const items = useMemo(() => data?.items ?? [], [data?.items])

  const tierCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, review: 0, auto_log: 0 }
    for (const a of items) {
      const t = a.tier ?? 'auto_log'
      counts[t] = (counts[t] ?? 0) + 1
    }
    return counts
  }, [items])

  const filteredItems = useMemo(() => {
    return items.filter((a) => {
      if (selectedTier && a.tier !== selectedTier) return false
      if (onlyZeroDay && !a.is_zero_day) return false
      if (search) {
        const query = search.toLowerCase()
        const text = `${a.id} ${a.src} ${a.dst} ${a.predicted} ${a.true_label} ${a.service} ${a.protocol}`.toLowerCase()
        if (!text.includes(query)) return false
      }
      return true
    }).sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0))
  }, [items, selectedTier, onlyZeroDay, search])

  async function handleReplay(alertId: string) {
    setReplaying(true)
    setReplayResult(null)
    try {
      const res = await fetch(`/api/detect/replay/${alertId}`, { method: 'POST' })
      if (!res.ok) throw new Error('Replay execution failed')
      const json = await res.json()
      setReplayResult(`Verified: ${json.predicted} · Priority: ${json.priority} (${json.tier})`)
    } catch (e) {
      setReplayResult(e instanceof Error ? e.message : 'Replay failed')
    } finally {
      setReplaying(false)
    }
  }

  if (error) {
    return (
      <div className="glass-card p-6 max-w-lg mx-auto text-center space-y-3">
        <AlertTriangle className="mx-auto text-rose-400" size={32} />
        <h2 className="text-lg font-bold text-white">Error Loading Alert Queue</h2>
        <p className="text-sm text-slate-400">{error}</p>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-3 text-slate-400">
        <div className="h-8 w-8 rounded-full border-2 border-emerald-400 border-t-transparent animate-spin" />
        <span className="text-sm font-medium">Loading Priority Incident Queue...</span>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in max-w-7xl mx-auto pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/8 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-amber-400">Problem 3 · Triage Engine</span>
            <span className="text-slate-600">·</span>
            <span className="text-xs font-mono text-slate-400">
              {data.source === 'elasticsearch' ? `${items.length} Indexed Incidents (Elasticsearch)` : `${items.length} Local Seed Flows`}
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">Incident Prioritisation Queue</h1>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="glass-pill px-3 py-1.5 rounded-xl text-xs font-mono text-slate-300 flex items-center gap-2">
            <Database size={13} className={data.source === 'elasticsearch' ? 'text-cyan-400' : 'text-amber-400'} />
            <span>Store: <strong className={data.source === 'elasticsearch' ? 'text-cyan-300' : 'text-amber-300'}>{data.source === 'elasticsearch' ? 'Elasticsearch (Live)' : 'Local Fallback'}</strong></span>
          </div>

          <div className="glass-pill px-3 py-1.5 rounded-xl text-xs font-mono text-slate-300">
            Cutoffs: <span className="text-rose-400 font-semibold">Crit ≥ {data.tier_cutoffs.critical?.toFixed(3)}</span> · <span className="text-amber-400 font-semibold">Rev ≥ {data.tier_cutoffs.review?.toFixed(3)}</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <ScrollSection delay={40}>
        <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-2xl glass-panel">
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setSelectedTier('')}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all ${
                selectedTier === ''
                  ? 'bg-white/15 text-white border border-white/20'
                  : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              All Tiers ({items.length})
            </button>

            <button
              onClick={() => setSelectedTier('critical')}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all flex items-center gap-1.5 ${
                selectedTier === 'critical'
                  ? 'bg-rose-500/25 text-rose-300 border border-rose-500/40'
                  : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-rose-400" />
              <span>Critical ({tierCounts.critical})</span>
            </button>

            <button
              onClick={() => setSelectedTier('review')}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all flex items-center gap-1.5 ${
                selectedTier === 'review'
                  ? 'bg-amber-500/25 text-amber-300 border border-amber-500/40'
                  : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              <span>Review ({tierCounts.review})</span>
            </button>

            <button
              onClick={() => setSelectedTier('auto_log')}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all flex items-center gap-1.5 ${
                selectedTier === 'auto_log'
                  ? 'bg-slate-700/50 text-slate-200 border border-slate-600'
                  : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <CheckCircle2 size={12} className="text-slate-400" />
              <span>Auto-Logged ({tierCounts.auto_log})</span>
            </button>
          </div>

          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs font-medium text-slate-300 cursor-pointer select-none px-2.5 py-1.5 rounded-xl hover:bg-white/5">
              <input
                type="checkbox"
                checked={onlyZeroDay}
                onChange={(e) => setOnlyZeroDay(e.target.checked)}
                className="rounded bg-slate-900 border-white/20 text-cyan-500 focus:ring-0"
              />
              <span className="text-cyan-400 font-semibold">Zero-Day Only</span>
            </label>

            <div className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search alert, IP, or service..."
                className="bg-black/30 border border-white/10 rounded-xl pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500/50 w-52 sm:w-64"
              />
            </div>
          </div>
        </div>
      </ScrollSection>

      {/* Main Split Layout: Table on Left + Slide-Over / Inspector on Right */}
      <ScrollSection delay={100}>
        <div className="grid lg:grid-cols-12 gap-6 items-start">
        {/* Left: Alerts Table */}
        <div className={`${activeAlert ? 'lg:col-span-7' : 'lg:col-span-12'} glass-card overflow-hidden border border-white/10`}>
          <div className="overflow-x-auto max-h-[680px] overflow-y-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-[#0d1424] border-b border-white/10 text-slate-400 font-medium z-10">
                <tr>
                  <th className="py-3 px-4">Priority / Tier</th>
                  <th className="py-3 px-4">Incident ID</th>
                  <th className="py-3 px-4">Predicted Family</th>
                  <th className="py-3 px-4">Target Asset</th>
                  <th className="py-3 px-4">Flow Path</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredItems.map((item) => {
                  const isSelected = activeAlert?.id === item.id
                  const tierMeta = TIER_CONFIG[item.tier ?? 'auto_log'] || TIER_CONFIG.auto_log
                  const prioPercent = Math.min(Math.max((item.priority ?? 0) * 100, 0), 100)

                  return (
                    <tr
                      key={item.id}
                      onClick={() => setActiveAlert(item)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? 'bg-emerald-500/10 hover:bg-emerald-500/15' : 'hover:bg-white/5'
                      }`}
                    >
                      {/* Priority Score & Tier Bar */}
                      <td className="py-3 px-4">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-white">
                              {(item.priority ?? 0).toFixed(3)}
                            </span>
                            <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${tierMeta.badgeClass}`}>
                              {tierMeta.label}
                            </span>
                          </div>
                          <div className="w-20 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                            <div
                              className="h-full rounded-full transition-all"
                              style={{ width: `${prioPercent}%`, backgroundColor: tierMeta.barColor }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Alert ID */}
                      <td className="py-3 px-4 font-mono">
                        <div className="font-medium text-slate-200">{item.id}</div>
                        {item.is_zero_day && (
                          <span className="inline-block mt-0.5 text-[9px] font-semibold px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                            NOVEL ZERO-DAY
                          </span>
                        )}
                      </td>

                      {/* Predicted Class */}
                      <td className="py-3 px-4">
                        <span className="font-semibold text-white capitalize">
                          {item.predicted.replace('_', ' ')}
                        </span>
                        <div className="text-[10px] text-slate-500 font-mono">
                          Conf: {(item.confidence * 100).toFixed(1)}%
                        </div>
                      </td>

                      {/* Service & Criticality */}
                      <td className="py-3 px-4 font-mono">
                        <div className="text-slate-300 font-medium">
                          {item.protocol}/{item.service}
                        </div>
                        <div className="text-[10px] text-slate-500">
                          Crit: {item.asset_criticality?.toFixed(2)}
                          {!item.asset_criticality_known && (
                            <span className="text-amber-400 font-sans ml-1">· unmapped</span>
                          )}
                        </div>
                      </td>

                      {/* Flow IPs */}
                      <td className="py-3 px-4 font-mono text-slate-400">
                        <div className="truncate max-w-[130px]">{item.src}</div>
                        <div className="text-slate-500 truncate max-w-[130px]">→ {item.dst}</div>
                      </td>

                      {/* View Action */}
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            setActiveAlert(item)
                          }}
                          className={`p-1.5 rounded-lg border transition-all ${
                            isSelected 
                              ? 'bg-emerald-500 text-slate-950 border-emerald-400' 
                              : 'border-white/10 text-slate-400 hover:text-white hover:bg-white/10'
                          }`}
                        >
                          <ArrowUpRight size={14} />
                        </button>
                      </td>
                    </tr>
                  )
                })}

                {filteredItems.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-500">
                      No alerts match the chosen filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Modern Slide-Over / Detail Inspector */}
        {activeAlert && (
          <div className="lg:col-span-5 glass-card p-6 space-y-6 border border-white/15 sticky top-20 animate-fade-in">
            {/* Drawer Header */}
            <div className="flex items-start justify-between border-b border-white/10 pb-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono text-slate-400 font-semibold">{activeAlert.id}</span>
                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${TIER_CONFIG[activeAlert.tier ?? 'auto_log']?.badgeClass}`}>
                    {TIER_CONFIG[activeAlert.tier ?? 'auto_log']?.label}
                  </span>
                  {activeAlert.is_zero_day && (
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                      ZERO-DAY
                    </span>
                  )}
                </div>
                <h3 className="text-xl font-bold text-white capitalize">
                  {activeAlert.predicted.replace('_', ' ')} Incident
                </h3>
              </div>

              <button
                onClick={() => setActiveAlert(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-white/10"
              >
                <X size={18} />
              </button>
            </div>

            {/* Quick Metrics Grid */}
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                <span className="text-slate-400">Composite Priority</span>
                <div className="text-xl font-bold font-mono text-emerald-400">
                  {activeAlert.priority.toFixed(4)}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                <span className="text-slate-400">Classifier Confidence</span>
                <div className="text-xl font-bold font-mono text-white">
                  {(activeAlert.confidence * 100).toFixed(1)}%
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                <span className="text-slate-400">Reconstruction Error</span>
                <div className="text-sm font-bold font-mono text-cyan-300">
                  {activeAlert.reconstruction_error.toFixed(4)}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                <span className="text-slate-400">Target Asset Criticality</span>
                <div className="text-sm font-bold font-mono text-amber-300">
                  {activeAlert.asset_criticality.toFixed(2)}
                  {!activeAlert.asset_criticality_known && (
                    <span className="text-[10px] font-sans font-normal text-amber-400 ml-1">(Floor)</span>
                  )}
                </div>
              </div>
            </div>

            {/* Priority Contribution Breakdown */}
            <div className="space-y-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                5-Factor Priority Breakdown
              </h4>
              <div className="space-y-2 text-xs">
                {Object.entries(activeAlert.priority_components ?? {}).map(([key, value]) => {
                  const percent = Math.min(Math.max((value / 0.35) * 100, 0), 100)
                  return (
                    <div key={key} className="space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="text-slate-400 capitalize">{key.replace('_', ' ')}</span>
                        <span className="font-mono text-slate-200 font-semibold">{value.toFixed(4)}</span>
                      </div>
                      <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="bg-emerald-400 h-full rounded-full"
                          style={{ width: `${percent}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Tier Routing Explanation */}
            <div className="p-3.5 rounded-xl bg-slate-900/80 border border-white/10 space-y-1 text-xs">
              <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                <ShieldCheck size={14} className="text-emerald-400" />
                Triage Policy Reason
              </span>
              <p className="text-slate-400 leading-relaxed text-[11px]">
                {activeAlert.tier_reason}
              </p>
            </div>

            {/* Replay Verification Button */}
            <div className="pt-2 border-t border-white/10 flex items-center justify-between gap-3">
              <button
                onClick={() => handleReplay(activeAlert.id)}
                disabled={replaying}
                className="flex-1 py-2.5 px-4 rounded-xl bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold text-xs hover:bg-emerald-500/30 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <RotateCw size={14} className={replaying ? 'animate-spin' : ''} />
                <span>{replaying ? 'Replaying Flow...' : 'Verify Via Live API Replay'}</span>
              </button>
            </div>

            {replayResult && (
              <div className="p-2.5 rounded-lg bg-black/40 border border-white/10 font-mono text-[11px] text-emerald-300">
                {replayResult}
              </div>
            )}
          </div>
        )}
        </div>
      </ScrollSection>
    </div>
  )
}
