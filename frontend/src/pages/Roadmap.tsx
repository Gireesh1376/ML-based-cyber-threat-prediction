import { 
  Radar, 
  Lock, 
  BellRing, 
  ShieldAlert, 
  ArrowRight
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { ScrollSection } from '../components/ScrollSection'

const problems = [
  {
    id: 'P1',
    title: 'Zero-Day / Unknown Attack Detection',
    subtitle: 'Dual-Model Autoencoder + XGBoost Hybrid',
    status: 'Implemented',
    badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    icon: Radar,
    metrics: [
      { label: 'Test Accuracy', val: '87.45%' },
      { label: 'Attack Recall', val: '84.13%' },
      { label: 'Zero-Day Catch', val: '76.37%' },
    ],
    body: 'An unsupervised neural network autoencoder learns normal traffic baseline. XGBoost scores known attack families. High reconstruction error with weak known-class confidence promotes flows into novel zero-days, complemented by SHAP explanations and per-feature error decomposition.',
    link: '/zero-day',
    linkLabel: 'Test in Zero-Day Studio',
  },
  {
    id: 'P2',
    title: 'Encrypted TLS / QUIC Traffic Blind Spot',
    subtitle: 'Metadata-Driven CNN-BiLSTM (No-Decryption)',
    status: 'Phase 2 (Planned)',
    badgeClass: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
    icon: Lock,
    metrics: [
      { label: 'Target Protocol', val: 'TLS 1.3 / ECH' },
      { label: 'Architecture', val: 'CNN-BiLSTM' },
      { label: 'Features', val: 'SPLT + JA4' },
    ],
    body: 'Privacy-preserving encrypted traffic analysis using packet length sequences, burst timing (SPLT), and TLS handshake attributes without intercepting or decrypting payload contents, conforming to NIST SP 1800-37 guidelines.',
    link: null,
    linkLabel: null,
  },
  {
    id: 'P3',
    title: 'Alert Fatigue & Prioritisation',
    subtitle: 'Composite Priority Score & Tiered Triage Flow',
    status: 'Implemented',
    badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    icon: BellRing,
    metrics: [
      { label: 'Auto-Log Rate', val: '47.67%' },
      { label: 'Critical Precision', val: '93.71%' },
      { label: 'Human Capture', val: '85.43%' },
    ],
    body: 'Automates 47.7% of routine traffic via normalized 5-factor composite priority (class-aware confidence + reconstruction anomaly + threat severity + asset criticality + zero-day bonus). Features an unknown-service Review floor ensuring unmapped assets are never silently auto-logged.',
    link: '/alerts',
    linkLabel: 'Open Triage Console',
  },
  {
    id: 'P4',
    title: 'Adversarial Evasion Robustness',
    subtitle: 'Constrained Perturbations & Adversarial Retraining',
    status: 'Implemented',
    badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    icon: ShieldAlert,
    metrics: [
      { label: 'Evasion Mitigation', val: '45.9%' },
      { label: 'Hardened Recall', val: '92.5%' },
      { label: 'FPR Penalty', val: '0.0%' },
    ],
    body: 'Hardens the tree-ensemble core against generative evasion attacks (such as DEMGAN and universal perturbations) using network-protocol constrained adversarial sample synthesis and iterative retraining passes.',
    link: '/adversarial',
    linkLabel: 'Open Defense Studio',
  },
]

export default function Roadmap() {
  return (
    <div className="space-y-8 animate-fade-in max-w-7xl mx-auto pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/8 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400">Strategic Roadmap</span>
            <span className="text-slate-600">·</span>
            <span className="text-xs font-mono text-slate-400">4-Problem Integrated Defense Vision</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">Four-Problem Strategic Program</h1>
        </div>

        <div className="glass-pill px-3 py-1.5 rounded-xl text-xs font-mono text-slate-300">
          Current Release: <span className="text-emerald-400 font-bold">Problems 1, 3 & 4 Built</span>
        </div>
      </div>

      {/* Program Overview Description */}
      <ScrollSection delay={40}>
        <div className="glass-card p-6 border border-white/10 space-y-2">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">Unified Threat Architecture</h2>
          <p className="text-xs text-slate-400 leading-relaxed max-w-4xl">
            Rather than deploying disconnected tools, the research design integrates the challenges into a single 
            cyber defense workflow. In this release, <strong>Problem 1 (Zero-Day Detection)</strong>, <strong>Problem 3 (Alert Prioritisation)</strong>, and <strong>Problem 4 (Adversarial Robustness)</strong> are 
            fully implemented and empirically validated on the NSL-KDD benchmark. Problem 2 represents the next planned phase in the architecture roadmap.
          </p>
        </div>
      </ScrollSection>

      {/* 4 Pillars Grid */}
      <ScrollSection delay={100}>
        <div className="grid md:grid-cols-2 gap-6">
          {problems.map((p) => {
            const Icon = p.icon
            const isImplemented = p.status === 'Implemented'

            return (
              <div
                key={p.id}
                className={`glass-card p-6 space-y-5 border transition-all ${
                  isImplemented ? 'border-white/15 hover:border-emerald-500/30' : 'border-white/5 opacity-85'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`h-10 w-10 rounded-xl grid place-items-center ${isImplemented ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-800 text-slate-400'}`}>
                      <Icon size={20} />
                    </div>
                    <div>
                      <span className="text-xs font-mono text-slate-500 font-bold">{p.id}</span>
                      <h3 className="text-base font-bold text-white">{p.title}</h3>
                    </div>
                  </div>

                  <span className={`text-[10px] font-mono px-2.5 py-1 rounded-full border ${p.badgeClass}`}>
                    {p.status}
                  </span>
                </div>

                <div className="text-xs font-medium text-slate-300 font-mono">
                  {p.subtitle}
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">
                  {p.body}
                </p>

                {/* Metric Indicators */}
                <div className="grid grid-cols-3 gap-2 pt-2 border-t border-white/5">
                  {p.metrics.map((m) => (
                    <div key={m.label} className="p-2 rounded-lg bg-black/25 space-y-0.5">
                      <span className="text-[10px] text-slate-500 block truncate">{m.label}</span>
                      <div className="text-xs font-bold font-mono text-slate-200">{m.val}</div>
                    </div>
                  ))}
                </div>

                {p.link && (
                  <div className="pt-2">
                    <Link
                      to={p.link}
                      className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1.5 group"
                    >
                      <span>{p.linkLabel}</span>
                      <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
                    </Link>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </ScrollSection>
    </div>
  )
}
