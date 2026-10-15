import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Radar,
  BellRing,
  ArrowRight,
  Sparkles,
  Layers,
  Gauge,
  Activity,
  ChevronRight,
  TrendingUp,
  FileCheck2,
  ShieldAlert
} from 'lucide-react'
import { getSummary, type Summary } from '../api'
import { useScrollReveal } from '../hooks/useScrollReveal'

export default function Landing() {
  const [summary, setSummary] = useState<Summary | null>(null)
  const [pillarRef, isPillarVisible] = useScrollReveal(0.08)
  const [capabilitiesRef, isCapVisible] = useScrollReveal(0.08)
  const [architectureRef, isArchVisible] = useScrollReveal(0.08)

  useEffect(() => {
    getSummary()
      .then(setSummary)
      .catch(() => setSummary(null))
  }, [])

  return (
    <div className="space-y-20 max-w-7xl mx-auto pb-16">
      {/* Hero Section with Staggered Fade-in */}
      <section className="relative pt-6 pb-8 text-center lg:text-left">
        {/* Subtle Ambient Radial Glow */}
        <div className="absolute -top-12 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-emerald-500/10 via-cyan-500/5 to-transparent rounded-full blur-3xl pointer-events-none" />

        <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full glass-pill mb-6 text-xs font-medium text-emerald-400 border border-emerald-500/20 animate-fade-in-down shadow-[0_0_15px_rgba(16,185,129,0.15)]">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-beacon" />
          <span>AEGIS v2.4 Security Engine · Dual-Model Hybrid Active</span>
          <span className="text-slate-600">|</span>
          <span className="font-mono text-slate-300">
            22,544 test flows replayed
          </span>
        </div>

        <div className="grid lg:grid-cols-12 gap-8 items-center">
          <div className="lg:col-span-7 space-y-6 animate-fade-in-up delay-200">
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white leading-[1.12]">
              ML-Based <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-cyan-400 to-indigo-400">Cyber Threat</span> Prediction
            </h1>
            <p className="text-base sm:text-lg text-slate-400 max-w-2xl font-normal leading-relaxed">
              A prototype evaluated on the NSL-KDD benchmark. Combines an unsupervised autoencoder for structural anomaly screening
              with an XGBoost classifier for known attack families, ranked by asset-aware composite priority.
            </p>

            <div className="flex flex-wrap items-center gap-4 pt-2 justify-center lg:justify-start">
              <Link
                to="/overview"
                className="inline-flex items-center gap-2 px-6 py-3.5 rounded-xl bg-gradient-to-r from-emerald-500 via-teal-500 to-emerald-600 text-slate-950 font-bold text-sm transition-all duration-200 shadow-lg shadow-emerald-500/25 hover:shadow-emerald-500/40 hover:scale-[1.03] active:scale-[0.98]"
              >
                <span>Launch Operations Center</span>
                <ArrowRight size={17} className="transition-transform group-hover:translate-x-1" />
              </Link>

              <Link
                to="/alerts"
                className="inline-flex items-center gap-2 px-5 py-3.5 rounded-xl glass-panel text-slate-200 font-medium text-sm hover:bg-white/10 hover:border-white/20 transition-all duration-200 hover:scale-[1.02] active:scale-[0.98]"
              >
                <BellRing size={16} className="text-amber-400" />
                <span>Incident Triage Console</span>
              </Link>

              <Link
                to="/zero-day"
                className="inline-flex items-center gap-2 px-5 py-3.5 rounded-xl glass-panel text-slate-300 font-medium text-sm hover:bg-white/10 hover:border-white/20 transition-all duration-200 hover:scale-[1.02] active:scale-[0.98]"
              >
                <Radar size={16} className="text-cyan-400" />
                <span>Zero-Day Studio</span>
              </Link>
            </div>
          </div>

          {/* Quick Telemetry Overview Card with Interactive Glass Lift */}
          <div className="lg:col-span-5 animate-fade-in-up delay-350">
            <div className="glass-card-interactive glass-card p-6 relative overflow-hidden border border-white/12 shadow-2xl">
              <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
              <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-5">
                <div className="flex items-center gap-2.5">
                  <div className="h-6 w-6 rounded-lg bg-cyan-500/10 text-cyan-400 grid place-items-center">
                    <Activity size={15} />
                  </div>
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">Replay summary</span>
                </div>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 font-medium">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  SYSTEM ACTIVE
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3.5">
                <div className="p-3.5 rounded-xl bg-slate-900/60 border border-white/5 hover:border-white/15 transition-all">
                  <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wide">Test Accuracy</div>
                  <div className="text-2xl font-bold text-white mt-1 font-mono">
                    {summary?.kpis?.test_accuracy ? `${(summary.kpis.test_accuracy * 100).toFixed(2)}%` : '87.45%'}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">Official NSL-KDD Test Split</div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-900/60 border border-white/5 hover:border-white/15 transition-all">
                  <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wide">Zero-Day Catch</div>
                  <div className="text-2xl font-bold text-cyan-400 mt-1 font-mono">
                    {summary?.kpis?.zero_day_detection_rate ? `${(summary.kpis.zero_day_detection_rate * 100).toFixed(1)}%` : '76.4%'}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">Held-Out Attack Families</div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-900/60 border border-white/5 hover:border-white/15 transition-all">
                  <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wide">Auto-Logged Rate</div>
                  <div className="text-2xl font-bold text-emerald-400 mt-1 font-mono">
                    {summary?.kpis?.auto_logged_share ? `${(summary.kpis.auto_logged_share * 100).toFixed(1)}%` : '47.7%'}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">Fatigue Reduction Ratio</div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-900/60 border border-white/5 hover:border-white/15 transition-all">
                  <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wide">Critical Precision</div>
                  <div className="text-2xl font-bold text-rose-400 mt-1 font-mono">
                    93.71%
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">High-Confidence Threat Tier</div>
                </div>
              </div>

              <div className="mt-5 pt-4 border-t border-white/5 flex items-center justify-between text-xs text-slate-400">
                <span className="flex items-center gap-1.5">
                  <FileCheck2 size={14} className="text-emerald-400" />
                  <span>Leaves test set untouched</span>
                </span>
                <Link to="/model" className="text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1 hover:underline">
                  <span>Model Card</span>
                  <ChevronRight size={14} />
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Core Architectural Pillars with Scroll-Driven Reveal */}
      <section
        ref={pillarRef}
        className={`space-y-6 reveal-on-scroll ${isPillarVisible ? 'is-revealed' : ''}`}
      >
        <div className="text-center max-w-2xl mx-auto space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full glass-pill text-xs font-mono text-slate-400 mb-1">
            <Sparkles size={13} className="text-cyan-400" />
            <span>Empirical Solutions</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">Two Problems Addressed, with Measured Results</h2>
          <p className="text-sm text-slate-400">
            Validated against leave-family-out benchmarks with comprehensive mathematical transparency.
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-6">
          {/* Pillar 1: Zero-Day */}
          <div className="glass-card-interactive glass-card p-7 space-y-5 border border-white/10 hover:border-cyan-500/40 relative overflow-hidden group">
            {/* Ambient Radar Scanner in corner */}
            <div className="absolute -top-12 -right-12 w-40 h-40 rounded-full border border-cyan-500/10 pointer-events-none flex items-center justify-center">
              <div className="w-full h-full rounded-full border border-cyan-500/20 animate-radar-ping pointer-events-none" />
              <div className="absolute w-20 h-20 rounded-full bg-gradient-to-tr from-cyan-500/20 to-transparent animate-radar-sweep pointer-events-none" />
            </div>

            <div className="flex items-center justify-between">
              <div className="h-12 w-12 rounded-2xl bg-cyan-500/10 text-cyan-400 grid place-items-center border border-cyan-500/20 group-hover:scale-105 transition-transform">
                <Radar size={24} />
              </div>
              <span className="text-xs font-mono px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                PROBLEM 1 · IMPLEMENTED
              </span>
            </div>

            <div className="space-y-2">
              <h3 className="text-xl font-bold text-white group-hover:text-cyan-300 transition-colors">
                Dual-Model Hybrid Zero-Day Detection
              </h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Supervised models miss unobserved attack signatures. Aegis pairs an unsupervised MLP autoencoder
                trained purely on benign network traffic with an XGBoost classifier. When traffic exhibits high reconstruction
                error and the classifier is unconfident, it is promoted to a novel threat.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 pt-2 text-xs">
              <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                <span className="text-slate-400">Hybrid Attack Recall</span>
                <div className="text-lg font-bold text-cyan-300 font-mono">84.1%</div>
                <span className="text-[10px] text-slate-500">vs ≤ 65.9% for supervised</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                <span className="text-slate-400">Zero-Day Family Catch</span>
                <div className="text-lg font-bold text-cyan-300 font-mono">76.4%</div>
                <span className="text-[10px] text-slate-500">vs ≤ 43.4% for baselines</span>
              </div>
            </div>

            <div className="pt-2">
              <Link
                to="/zero-day"
                className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1.5 group/btn"
              >
                <span>Interactive Zero-Day Studio</span>
                <ArrowRight size={14} className="group-hover/btn:translate-x-1 transition-transform" />
              </Link>
            </div>
          </div>

          {/* Pillar 2: Alert Fatigue */}
          <div className="glass-card-interactive glass-card p-7 space-y-5 border border-white/10 hover:border-emerald-500/40 relative overflow-hidden group">
            <div className="flex items-center justify-between">
              <div className="h-12 w-12 rounded-2xl bg-emerald-500/10 text-emerald-400 grid place-items-center border border-emerald-500/20 group-hover:scale-105 transition-transform">
                <Gauge size={24} />
              </div>
              <span className="text-xs font-mono px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                PROBLEM 3 · IMPLEMENTED
              </span>
            </div>

            <div className="space-y-2">
              <h3 className="text-xl font-bold text-white group-hover:text-emerald-300 transition-colors">
                Composite Prioritization & Tiered Triage
              </h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Raw volume overwhelms security analysts. Every alert is scored on a normalized $[0, 1]$ composite priority
                combining class-aware attack confidence, reconstruction anomaly, threat family severity, asset criticality,
                and novelty bonus into Critical, Review, and Auto-logged tiers.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 pt-2 text-xs">
              <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                <span className="text-slate-400">Workload Reduction</span>
                <div className="text-lg font-bold text-emerald-300 font-mono">47.7%</div>
                <span className="text-[10px] text-slate-500">Auto-logged routine flows</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                <span className="text-slate-400">Critical Tier Precision</span>
                <div className="text-lg font-bold text-emerald-300 font-mono">93.7%</div>
                <span className="text-[10px] text-slate-500">85.4% attacks retained</span>
              </div>
            </div>

            <div className="pt-2">
              <Link
                to="/alerts"
                className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1.5 group/btn"
              >
                <span>Explore Incident Triage Queue</span>
                <ArrowRight size={14} className="group-hover/btn:translate-x-1 transition-transform" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Architecture Flow Section with Scroll Reveal */}
      <section
        ref={architectureRef}
        className={`glass-card p-8 border border-white/10 space-y-6 reveal-on-scroll ${isArchVisible ? 'is-revealed' : ''}`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
          <div>
            <h3 className="text-lg font-bold text-white">Parallel Dual-Model Detection Pipeline</h3>
            <p className="text-xs text-slate-400 mt-0.5">Scored simultaneously without sequential bottleneck.</p>
          </div>
          <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20">
            Validated Leave-Family-Out
          </span>
        </div>

        <div className="grid sm:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900/70 border border-white/5 space-y-2 hover:border-cyan-500/30 transition-all">
            <div className="flex items-center gap-2 text-cyan-400 font-bold">
              <Radar size={16} />
              <span>1. Normal Traffic Autoencoder</span>
            </div>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Trained exclusively on benign flows. Measures squared reconstruction error vs threshold ($\theta = 0.2471$).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/70 border border-white/5 space-y-2 hover:border-emerald-500/30 transition-all">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <Layers size={16} />
              <span>2. Supervised XGBoost Classifier</span>
            </div>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Trained on known families (`normal`, `dos`, `probe`, `r2l`, `u2r`). Delivers softmax confidence reading.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/70 border border-white/5 space-y-2 hover:border-indigo-500/30 transition-all">
            <div className="flex items-center gap-2 text-indigo-400 font-bold">
              <Gauge size={16} />
              <span>3. Novelty Gate & Composite Triage</span>
            </div>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Promotes to `zero_day` when anomalous AND unconfident in known class, then prioritizes for human triage.
            </p>
          </div>
        </div>
      </section>

      {/* Design Highlights Grid with Scroll Reveal */}
      <section
        ref={capabilitiesRef}
        className={`space-y-6 reveal-on-scroll ${isCapVisible ? 'is-revealed' : ''}`}
      >
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-white/10 pb-4">
          <div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">Design Highlights</h2>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">Design choices built into the pipeline.</p>
          </div>
          <span className="text-xs font-mono text-slate-500">FastAPI · React 19 · TypeScript · XGBoost</span>
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-5 rounded-2xl glass-card space-y-3 hover:border-indigo-500/30 transition-all">
            <div className="h-9 w-9 rounded-xl bg-indigo-500/10 text-indigo-400 grid place-items-center">
              <ShieldAlert size={18} />
            </div>
            <h4 className="font-semibold text-white text-sm">Unknown Service Review Floor</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Unmapped services are never silently auto-logged. They are floored to the Review tier with data-quality audit flags.
            </p>
          </div>

          <div className="p-5 rounded-2xl glass-card space-y-3 hover:border-amber-500/30 transition-all">
            <div className="h-9 w-9 rounded-xl bg-amber-500/10 text-amber-400 grid place-items-center">
              <Sparkles size={18} />
            </div>
            <h4 className="font-semibold text-white text-sm">Dual Explainability</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              SHAP feature impacts explain the classifier; per-feature squared error shares explain why zero-days appear anomalous.
            </p>
          </div>

          <div className="p-5 rounded-2xl glass-card space-y-3 hover:border-rose-500/30 transition-all">
            <div className="h-9 w-9 rounded-xl bg-rose-500/10 text-rose-400 grid place-items-center">
              <TrendingUp size={18} />
            </div>
            <h4 className="font-semibold text-white text-sm">Leave-Family-Out Validation</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Novelty thresholds were derived on validation pseudo-zero-days; final novelty settings were chosen on validation data only.
            </p>
          </div>

          <div className="p-5 rounded-2xl glass-card space-y-3 hover:border-cyan-500/30 transition-all">
            <div className="h-9 w-9 rounded-xl bg-cyan-500/10 text-cyan-400 grid place-items-center">
              <Layers size={18} />
            </div>
            <h4 className="font-semibold text-white text-sm">Replay Reproduction</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Every alert stores its exact raw feature vector for deterministic replay through the backend pipeline.
            </p>
          </div>
        </div>
      </section>
    </div>
  )
}