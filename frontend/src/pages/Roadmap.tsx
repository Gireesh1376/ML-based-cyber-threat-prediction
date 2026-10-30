import { useEffect, useState } from 'react'
import {
  Radar,
  Lock,
  BellRing,
  ShieldAlert,
  ArrowRight,
  Database,
  Workflow,
  ShieldCheck,
  Bot,
  LayoutDashboard,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Shield,
  Sparkles,
  ChevronRight,
  Info,
  Sliders,
  TestTube,
  Scale,
  GitFork,
  Boxes
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { getSummary, type Summary } from '../api'
import { ScrollSection } from '../components/ScrollSection'

type TabKey = 'all' | 'foundation' | 'modules' | 'stages' | 'matrix'

export default function Roadmap() {
  const [summary, setSummary] = useState<Summary | null>(null)
  const [activeTab, setActiveTab] = useState<TabKey>('all')

  useEffect(() => {
    getSummary().then(setSummary).catch(() => setSummary(null))
  }, [])

  // ---------------------------------------------------------------------------
  // 1. Foundational Research Problems (P1 – P4)
  // Preserves existing technical baseline while auditing architecture & metrics
  // ---------------------------------------------------------------------------
  const foundationalProblems = [
    {
      id: 'P1',
      title: 'Zero-Day / Unknown Attack Detection',
      subtitle: 'MLPRegressor Bottleneck Reconstruction Network + XGBoost Hybrid Detector',
      status: 'Validated Baseline',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      icon: Radar,
      metrics: [
        {
          label: 'Official Test Binary',
          val: summary?.kpis?.test_accuracy != null
            ? `${(summary.kpis.test_accuracy * 100).toFixed(2)}% Acc / ${(summary.kpis.test_recall != null ? (summary.kpis.test_recall * 100).toFixed(1) : '84.1')}% Rec`
            : '87.45% Acc / 84.1% Rec (Saved Ref)',
          sub: 'Official NSL-KDD test set (12,833 attacks)'
        },
        {
          label: 'Held-Out Zero-Day Catch',
          val: summary?.kpis?.zero_day_detection_rate != null
            ? `${(summary.kpis.zero_day_detection_rate * 100).toFixed(2)}%`
            : '76.37% (Saved Ref)',
          sub: '2,725 / 3,568 unseen novel attack flows detected'
        },
        {
          label: 'Explicit Zero-Day Screening',
          val: 'P: 51.6% · R: 49.4% · F1: 0.50',
          sub: 'Screening signal for analyst review, not verdict'
        },
      ],
      architectureNote: 'Implemented via scikit-learn MLPRegressor bottleneck reconstruction network (hidden layers: (64, 24, 8, 24, 64)) trained on benign traffic (X → X) coupled with an XGBoost classifier on 48 selected features. Novelty gate flags anomalies with weak known-class confidence (< 0.90).',
      body: 'Combines an unsupervised MLPRegressor bottleneck reconstruction network baseline with supervised tree classifiers. Disaggregates official test accuracy from held-out zero-day capture and explicit zero-day screening signals, with SHAP feature attribution and reconstruction error decomposition.',
      futureResearch: [
        'GAN-based synthetic attack sample generation for augmenting low-density attack spaces.',
        'CTGAN and modern tabular generative models as alternatives for structured flow records.',
        'Targeted rare attack family detection, specifically addressing lower recall on R2L (~45%) and U2R (~66%).',
        'Improved unknown-attack generalisation across broader network topographies and protocol variations.',
        'Statistical concept drift detection for dynamically tracking shifting network flow distributions.',
        'Continual and incremental learning pipelines to incorporate verified new attack signatures without catastrophic forgetting.',
        'Confidence calibration (temperature/Platt scaling) and dynamic threshold optimisation.',
        'Evaluation on diverse, modern network intrusion corpora (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15).'
      ],
      link: '/zero-day',
      linkLabel: 'Test in Zero-Day Studio',
    },
    {
      id: 'P2',
      title: 'Encrypted TLS / Traffic Threat Detection',
      subtitle: 'Metadata-Driven Gradient-Boosted Trees (SPLT + JA4 + Transport Dynamics)',
      status: 'Validated Baseline',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      icon: Lock,
      metrics: [
        {
          label: 'Primary Reproducible Holdout',
          val: '98.50% Acc · 98.76% Rec',
          sub: '234,037 flows across 9,948 execution groups (Sept 2025)'
        },
        {
          label: 'Precision & F1 / Benign FPR',
          val: '97.99% Prec · 0.9837 F1 · 1.72% FPR',
          sub: 'ROC-AUC 0.9988 · PR-AUC 0.9984 (100% bit-for-bit reproducible)'
        },
        {
          label: 'Zero-Day Holdout Recall',
          val: '93.94% (697 / 742)',
          sub: '12 unseen malware families (Historical Draw 1: 97.99% Acc / 2.15% FPR)'
        },
      ],
      architectureNote: 'Designed around privacy-preserving encrypted-traffic metadata analysis without payload decryption (71-feature transformer: SPLT packet lengths/times, JA4 fingerprint prefix, cipher suite entropy, connection dynamics). Operates in offline flow record ingestion & calibrated preset mode.',
      scopeLimitation: 'The current implementation does NOT provide live network-interface traffic capture, arbitrary raw PCAP parsing/dissection (the /api/encrypted/analyze-pcap endpoint returns HTTP 501 Not Implemented), or payload decryption. Current detection operates exclusively on supplied pre-extracted connection metadata records.',
      body: 'Analyzes encrypted session dynamics using packet sequences and handshake telemetry without decrypting payload contents. Evaluated against a rigorous 234,037 holdout benchmark with 100% bit-for-bit reproducibility.',
      futureResearch: [
        'Live network-interface traffic capture (AF_PACKET / DPDK zero-copy drivers).',
        'PCAP upload, validation, and automated flow reassembly pipelines.',
        'Reliable bidirectional flow extraction and session tracking.',
        'Zeek / Scapy-based telemetry extraction where appropriate.',
        'TLS 1.3 and, where technically supported, QUIC transport metadata analysis (connection IDs, initial packet lengths).',
        'Real-time streaming feature extraction and sub-millisecond inference.',
        'Streaming traffic processing via Kafka / message queue ingestion.',
        'Encrypted-flow behavioural baselines and SNI reputation scoring.',
        'Performance and latency optimisation for multi-gigabit enterprise links (≥ 10 Gbps) [Provisional Engineering Target — To Be Validated].'
      ],
      link: '/encrypted',
      linkLabel: 'Open Encrypted Lab',
    },
    {
      id: 'P3',
      title: 'Alert Fatigue & Prioritisation',
      subtitle: 'Class-Aware 5-Factor Composite Priority Score & Tiered Triage Engine',
      status: 'Validated Baseline',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      icon: BellRing,
      metrics: [
        {
          label: 'Safe Auto-Log Rate',
          val: summary?.problem3?.workload?.auto_logged_share != null
            ? `${(summary.problem3.workload.auto_logged_share * 100).toFixed(2)}%`
            : '47.67% (Saved Ref)',
          sub: '10,746 routine test flows filtered from human queue'
        },
        {
          label: 'Critical Tier Precision',
          val: summary?.problem3?.per_tier?.critical?.precision != null
            ? `${(summary.problem3.per_tier.critical.precision * 100).toFixed(2)}%`
            : '93.71% (Saved Ref)',
          sub: '9,537 true attacks captured in 10,177 critical alerts'
        },
        {
          label: 'Human Threat Preservation',
          val: summary?.problem3?.threat_preservation?.attacks_in_human_tiers != null
            ? `${(summary.problem3.threat_preservation.attacks_in_human_tiers * 100).toFixed(2)}%`
            : '85.43% (Saved Ref)',
          sub: '85.4% attacks & 78.2% zero-days reach human tiers (52.3% workload)'
        },
      ],
      architectureNote: 'Normalized 5-factor composite priority (class-aware confidence + reconstruction anomaly + threat severity + asset criticality + zero-day bonus). Features an unknown-service Review floor (0.5 default) preventing silent auto-logging.',
      scopeLimitation: 'Upstream Dependency: Prioritisation cannot recover threats missed by upstream detection. 14.6% of attacks (21.8% of zero-days) are auto-logged because both detectors confidently classified them as normal with near-zero anomaly error.',
      body: 'Reduces analyst alert fatigue by sorting flows into Critical, Review, and Auto-logged tiers using validation-derived quantiles, providing transparent tier reasons, component attribution, and data quality flags.',
      futureResearch: [
        'Cross-sensor alert correlation grouping related alerts across network sensors and endpoints.',
        'Temporal deduplication clustering repeated events from identical source/destination pairs.',
        'Incident-level risk aggregation across multi-stage attack campaigns.',
        'Context-sensitive false-positive reduction based on historical baseline suppressions.',
        'Asset inventory and CMDB integration (ServiceNow, Device42).',
        'Dynamic asset criticality factoring real-time crown-jewel tagging and exposure scores.',
        'Alert lifecycle management (state machine: New → Triage → Investigating → Resolved → Closed).',
        'SLA tracking, auto-assignment, and analyst workload distribution.',
        'Priority score explainability decomposing the 5 contributing terms for transparent auditability.',
        'Analyst feedback loops and interactive triage tuning to adapt weights to organizational risk tolerance.'
      ],
      link: '/alerts',
      linkLabel: 'Open Triage Console',
    },
    {
      id: 'P4',
      title: 'Adversarial Evasion Robustness',
      subtitle: 'Protocol-Constrained Perturbations & Adversarial Retraining (ε = 0.20 Benchmark)',
      status: 'Validated Baseline',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      icon: ShieldAlert,
      metrics: [
        {
          label: 'Evasion Mitigation',
          val: summary?.adversarial?.summary?.evasion_reduction_pct != null
            ? `+${summary.adversarial.summary.evasion_reduction_pct}%`
            : '+28.8% DEMGAN / +55.8% FGSM / +89.6% UAP',
          sub: 'Hybrid evasion drop across FGSM, UAP & DEMGAN surrogate'
        },
        {
          label: 'Clean Recall Preserved',
          val: summary?.adversarial?.summary?.hardened_attack_recall != null
            ? `${(summary.adversarial.summary.hardened_attack_recall * 100).toFixed(1)}%`
            : '87.60% (Clean Acc: 89.77%)',
          sub: 'Zero clean performance degradation (-0.07% abs delta)'
        },
        {
          label: 'False Alarm Penalty',
          val: summary?.adversarial?.clean_metrics?.fpr_penalty != null
            ? `${(summary.adversarial.clean_metrics.fpr_penalty * 100).toFixed(1)}%`
            : '0.0% Penalty (FPR: 8.07%)',
          sub: '100.0% network protocol constraint validity'
        },
      ],
      architectureNote: 'Evaluates two-sided numerical Constrained FGSM, Universal Adversarial Perturbations (UAP), and DEMGAN empirical manifold drift approximation. The XGBoost classifier is retrained on 149,973 samples, backed by the MLPRegressor bottleneck reconstruction anomaly gate as defense-in-depth.',
      scopeLimitation: 'DEMGAN Implementation Note: The current DEMGAN implementation is an empirical manifold-drift surrogate approximation drifting features toward benign centroids with calibrated jitter, NOT a trained neural GAN generator. No neural GAN generator exists in the current codebase.',
      body: 'Hardens tree-ensembles against gradient and distribution perturbations under strict protocol constraints (clamped rates, discrete counts, TCP/UDP semantics, header immutability), maintaining clean detection accuracy without false alarm penalties.',
      futureResearch: [
        'Fully trained GAN-based synthetic network traffic generation (see dedicated research section below).',
        'CTGAN and modern tabular generative models for structured network-flow data.',
        'Synthetic rare-attack generation focusing on low-support classes (R2L, U2R).',
        'Adversarial sample generation for systematic detector stress-testing.',
        'Domain-constrained generation preserving valid feature and protocol relationships.',
        'Systematic adversarial retraining experiments using generated samples.',
        'Evaluation of generated-data realism and sample diversity (Wasserstein distance, Jensen-Shannon divergence).',
        'Direct empirical comparison against SMOTE, ADASYN, and heuristic augmentation baselines.',
        'Verification against train/test contamination and data leakage.',
        'Evaluation on untouched chronological splits and family-held-out zero-day datasets.'
      ],
      link: '/adversarial',
      linkLabel: 'Open Defense Studio',
    },
  ]

  // ---------------------------------------------------------------------------
  // 2. Eight Functional Capability Modules (A – H)
  // Comprehensive SaaS Architecture & Scope
  // ---------------------------------------------------------------------------
  const functionalModules = [
    {
      letter: 'A',
      title: 'Security Data Collection & Ingestion',
      category: 'Telemetry & Ingestion',
      icon: Database,
      status: 'Planned Engineering',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      currentVerified: 'Offline CSV batch ingestion, NSL-KDD benchmark replay, and synthetic flow presets.',
      missingWork: 'Live network-interface packet capture, PCAP parsing, streaming queues, and OCSF normalization.',
      targetStage: 'Stage 3 (Core Telemetry) & Stage 4 (Retention/Archival)',
      scope: [
        'Live network-interface traffic capture via zero-copy drivers (AF_PACKET / DPDK).',
        'PCAP upload, validation, parsing, and automated flow reassembly pipelines.',
        'High-throughput NetFlow (v5/v9), IPFIX, sFlow, and cloud VPC flow log ingestion.',
        'Firewall, endpoint, server, and cloud audit logs (Syslog, Windows EVTX, auditd, cloud trails).',
        'Zeek and Suricata security telemetry extraction and flow enrichment.',
        'Scalable streaming ingestion via distributed message queues (Kafka / RabbitMQ / Redis Streams).',
        'Event normalization to open standards (Open Cybersecurity Schema Framework OCSF / Elastic ECS).',
        'Network context enrichment: GeoIP, autonomous system numbers (ASN), and reverse DNS resolution.',
        'Data validation, schema sanitization, and graceful malformed-record dead-letter handling.',
        'Policy-driven data tiering (hot/warm/cold), automated archival, and AES-256 / TLS 1.3 encryption.',
        'Extensible connector ecosystem supporting modular REST APIs, webhooks, and rate-limited endpoints.'
      ],
    },
    {
      letter: 'B',
      title: 'Threat Detection & Analytics',
      category: 'Analytics Engine & Model Intelligence',
      icon: Radar,
      status: 'Implemented (Partial Baseline)',
      badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
      currentVerified: 'Problem 1 MLPRegressor bottleneck reconstruction network + XGBoost hybrid detector, Problem 2 SPLT + JA4 encrypted flow classifier, Problem 4 adversarially retrained hardened detector.',
      missingWork: 'Live flow feature extraction, GAN/CTGAN generative research, UEBA behavioral baselines, threat intel feeds, Sigma rule engine, and platform-wide Model Intelligence & Lifecycle Management.',
      targetStage: 'Stage 2 (Model Strengthening) & Stage 3 (SecOps Expansion)',
      scope: [
        'Known attack family detection via supervised tree-ensembles (Validated in P1/P2).',
        'Anomaly and novel attack pattern detection via MLPRegressor bottleneck reconstruction network (Validated in P1).',
        'Encrypted traffic behavioral threat analysis without payload decryption (Validated in P2).',
        'Adversarial evasion hardening and constrained retraining (Validated in P4).',
        'GAN/CTGAN research for synthetic network traffic generation & stress testing (Experimental Research).',
        'Targeted rare attack detection focusing on low-support classes (R2L and U2R).',
        'Unknown attack discovery and automated novel threat candidate clustering.',
        'Statistical concept drift detection for dynamically tracking shifting traffic distributions.',
        'Continual and incremental learning to adapt models without catastrophic forgetting.',
        'Behavioral threat analytics: User & Entity Behavior Analytics (UEBA) and baseline deviations.',
        'Beaconing frequency analysis, long-tail connection anomalies, and lateral movement detection.',
        'Threat intelligence lifecycle management: STIX/TAXII 2.1 IOC ingestion, matching, and aging.',
        'Detection engineering: custom Sigma and YARA-L rules engine with version control and testing.',
        'Dataset & Experiment Governance: versioning, quality validation, train/val/test isolation, and auditability.',
        'Model Registry & Versioning: artifact registry, metadata tracking, feature transformer compatibility, and deployment history.',
        'Model Performance Monitoring: per-attack-family metrics, FPR/FNR trends, concept drift, and confidence calibration.',
        'Controlled Retraining: trigger policies, regression testing against baselines, rare attack checks, and human sign-off.',
        'Deployment & Recovery: versioned model rollouts, canary/staged deployment, automated rollback, and reproducible restoration.'
      ],
    },
    {
      letter: 'C',
      title: 'Alert Intelligence & Prioritisation',
      category: 'Triage & Scoring',
      icon: BellRing,
      status: 'Implemented (Partial Baseline)',
      badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
      currentVerified: 'Problem 3 five-factor class-aware composite scoring with dynamic Critical/Review/Auto-log tiers and unknown-service Review floor.',
      missingWork: 'Cross-sensor correlation, temporal deduplication, incident-level scoring, CMDB integration, and alert lifecycle state management.',
      targetStage: 'Stage 2 (Model Strengthening) & Stage 3 (SecOps Expansion)',
      scope: [
        'Class-aware composite risk scoring balancing confidence, anomaly, severity, and asset impact (Validated in P3).',
        'Asset criticality assessment with documented unknown-service Review floor (Validated in P3).',
        'Cross-sensor alert correlation clustering related events across network sensors and endpoints.',
        'Temporal deduplication clustering repeated events from identical host pairs into unified alerts.',
        'Incident-level risk aggregation combining multi-stage alert scores into campaign severity.',
        'Context-sensitive false-positive reduction based on historical baseline suppressions.',
        'Asset inventory and CMDB integration (ServiceNow, Device42) for dynamic asset value synchronization.',
        'Comprehensive alert lifecycle management (state machine: New → Triage → Investigating → Resolved → Closed).',
        'SLA tracking, auto-assignment, and analyst workload distribution.',
        'Priority score explainability decomposing the contributing terms for transparent auditability.',
        'Analyst feedback loops and interactive triage tuning to adapt scoring to organizational risk tolerance.'
      ],
    },
    {
      letter: 'D',
      title: 'Investigation & Incident Management',
      category: 'SOC Workflows',
      icon: FileText,
      status: 'Planned Engineering',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      currentVerified: 'Incident triage priority queue, alert replay inspector, and SHAP feature explainability.',
      missingWork: 'Incident entity grouping, interactive attack timelines, evidence binders, MITRE ATT&CK mapping, and compliance reports.',
      targetStage: 'Stage 3 (Core SecOps) & Stage 4 (Enterprise Readiness)',
      scope: [
        'Automated incident creation, multi-alert grouping, severity scoping, and owner assignment.',
        'Multi-alert investigation consoles enabling cross-sensor pivoting and correlation.',
        'Interactive attack timelines tracing events chronologically across the cyber kill chain.',
        'Comprehensive MITRE ATT&CK enterprise technique mapping and coverage heatmaps.',
        'Cryptographic evidence collection, raw flow artifact capture, and chain-of-custody verification.',
        'Collaborative investigation notes, analyst scratchpads, and shared investigation workspaces.',
        'Audit-ready incident and compliance reporting (NIST CSF, ISO 27001, SOC 2, HIPAA).',
        'Threat intelligence context linking internal incident indicators to external adversary campaigns.',
        'Investigation history and immutable analyst audit trails recording all forensic actions.'
      ],
    },
    {
      letter: 'E',
      title: 'Response & Security Automation',
      category: 'Orchestration & Response',
      icon: Workflow,
      status: 'Planned Engineering',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      currentVerified: 'Triage tier recommendations, lab simulation controls, and priority queue sorting.',
      missingWork: 'Automated response playbooks, ticketing dispatch, SOAR connectors, and forensic artifact capture.',
      targetStage: 'Stage 3 (Integrations) & Stage 4 (SaaS Readiness)',
      scope: [
        'Contextual response recommendations per threat family, asset criticality, and alert tier.',
        'Configurable visual response playbooks for containment, artifact gathering, and mitigation.',
        'Analyst-approved response workflows: mandatory human authorization for active containment actions.',
        'Strict guardrails: No autonomous blocking or disruptive actions without explicit analyst sign-off.',
        'Enterprise ticketing integrations (ServiceNow, Jira Service Management, PagerDuty, Slack, Teams).',
        'Enterprise SOAR bi-directional handoff (Cortex XSOAR, Splunk SOAR, Swimlane).',
        'Automated forensic collection workflows (host memory capture, process tree extraction, netstat snapshot).',
        'Response execution history and containment audit trails recording authorization and execution status.'
      ],
    },
    {
      letter: 'F',
      title: 'Enterprise Management & SaaS Governance',
      category: 'Foundational SaaS Requirements & Tenant Trust',
      icon: ShieldCheck,
      status: 'Planned Engineering (Foundational Requirement)',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      currentVerified: 'System health liveness probe, database connection status telemetry, and offline fallback mode.',
      missingWork: 'Multi-tenant architecture, 10 cryptographic isolation boundaries, automated negative authorization tests, RBAC, SSO/MFA, API quotas, and audit logging.',
      targetStage: 'Stage 1 (Architecture Design) & Stage 4 (SaaS Platform Readiness)',
      scope: [
        'Multi-tenant architecture designed from the ground up prior to onboarding external customers.',
        'Ten Security Boundaries: Database-level isolation, object storage isolation, cache & queue isolation, API context authorization, background job isolation, model dataset & artifact isolation, log/export/backup isolation, administrative RBAC, secrets management, and tenant auditability.',
        'Automated negative security testing verifying cross-tenant access denial across IDOR, API endpoints, background jobs, exports, admin functions, and model retrieval.',
        'Organisation and workspace management for MSSPs, business units, and distributed SOC teams.',
        'Authentication and secure session management with token rotation and inactivity timeouts.',
        'Fine-grained Role-Based Access Control (RBAC: Viewer, Analyst, Lead, Admin) and permission boundaries.',
        'Enterprise Single Sign-On (SSO via SAML 2.0 / OIDC) and mandatory Multi-Factor Authentication (MFA).',
        'Scoped API keys, programmatic access management, rate limiting, and tenant usage quotas.',
        'Immutable, tamper-evident audit logging recording user logins, triage decisions, and model changes.',
        'Tenant-specific detection configuration, policy overrides, and custom suppression rules.',
        'Secure data retention policies, automated cold archival, and cryptographic data deletion.',
        'Model and detection-rule versioning tracking lineages, training sets, and canary deployment gates.',
        'Enterprise secrets management (HashiCorp Vault / envelope encryption).',
        'Operational resilience: distributed high availability (HA), automated backups, and disaster recovery (DR).',
        'Platform health monitoring, operational observability, and administrative controls.'
      ],
    },
    {
      letter: 'G',
      title: 'Future AI-Powered Capabilities',
      category: 'Governed AI & Assistive Analytics',
      icon: Bot,
      status: 'Long-Term Exploratory Vision',
      badgeClass: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
      currentVerified: 'SHAP tree feature attribution and per-feature reconstruction error decomposition.',
      missingWork: 'LLM security assistant, natural-language query parsing, automated summaries, and AI safety guardrails.',
      targetStage: 'Stage 5 (Governed AI Integration) — Optional Parallel Workstream',
      isFuture: true,
      scope: [
        'Conversational AI Security Analyst Assistant providing natural-language incident explanations and guidance.',
        'Natural-language threat investigation converting analyst questions into structured queries (Text-to-SQL/ES).',
        'Automated incident summarisation generating executive handoff reports and post-incident reviews.',
        'Shift handoff reports synthesizing multi-analyst investigations and outstanding triage queues.',
        'AI-assisted detection rule drafting: synthesizing Sigma/YARA-L rules from threat intelligence advisories.',
        'Evidence-grounded investigation assistance: no authoritative conclusions without verifiable evidence.',
        'Supervised agentic investigation workflows gathering evidence autonomously under strict human approval.',
        'Mandatory human sign-off for any consequential or active containment actions recommended by AI.',
        'Prompt-injection protection and adversarial input sanitization layers (≥ 99% mitigation benchmark target).',
        'Retrieval-Augmented Generation (RAG) grounding and hallucination controls bounded by tenant data.',
        'Immutable AI activity audit trails recording all prompts, generated outputs, and analyst approval states.'
      ],
    },
    {
      letter: 'H',
      title: 'Future Product Experience',
      category: 'UI/UX & Operational Visualization',
      icon: LayoutDashboard,
      status: 'Long-Term Exploratory Vision',
      badgeClass: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
      currentVerified: 'React + Vite + Tailwind SOC dashboard v2.4 (Executive Hub, Overview, Triage Queue, Labs, Model Intel).',
      missingWork: 'Tenant-specific dashboards, modular customizable layouts, streaming charts, and interactive attack graphs.',
      targetStage: 'Stage 6 (Experience & Commercial Validation) — Decoupled from Stage 5 AI dependencies',
      isFuture: true,
      scope: [
        'Enterprise-grade SOC user experience redesign optimized for multi-monitor operations centers.',
        'Tenant-specific and role-tailored dashboard views for executives, tier-1 analysts, and incident responders.',
        'Fully customizable dashboards with drag-and-drop KPI widgets and analyst layout presets.',
        'Real-time streaming telemetry monitoring with dynamic queue throughput counters and live indicators.',
        'Dedicated incident workspaces integrating attack chronologies, evidence binders, and team scratchpads.',
        'Interactive attack graphs rendering node-link topology and multi-hop attack campaigns.',
        'Unified forensics workbench integrating raw packet dissection with SHAP feature explainability.',
        'Model performance dashboards tracking live accuracy, recall, and concept drift over time.',
        'Executive security posture reporting tracking MTTD, MTTR, and alert fatigue reduction metrics.',
        'Organisation-level usage, quota consumption, and platform health telemetry dashboards.'
      ],
    },
  ]

  // ---------------------------------------------------------------------------
  // 3. Sequential Development Lifecycle (Stages 1 through 6)
  // Structured Dependency Sequence from Validated ML to SaaS Commercialization
  // ---------------------------------------------------------------------------
  const developmentStages = [
    {
      stage: 'Stage 1',
      title: 'Product Discovery and Architecture',
      status: 'In Progress',
      badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
      summary: 'Complete codebase audit, target customer & SOC workflow definition, modular decoupling, and tenant-aware architecture.',
      objectives: [
        'Execute complete repository and capability audit verifying baseline models, data pipelines, and limitations.',
        'Define target customer profiles and SecOps analyst workflows (Tier 1 triage, Tier 2 forensics, SOC Lead, CISO).',
        'Establish modular decoupled service boundaries and microservice contracts.',
        'Design multi-tenant architecture and strict tenant-level cryptographic data isolation boundaries (10 security boundaries) upfront.',
        'Publish formal OpenAPI 3.1 contracts and standardized event schemas (OCSF / ECS).',
        'Conduct security threat modelling (STRIDE, zero-trust data boundaries) across all ingestion and API paths.',
        'Establish Model Intelligence and Lifecycle Management framework design (dataset governance, registry, drift, retraining policies).',
        'Establish research, testing, CI/CD pipeline, and model governance standards.'
      ],
      dependencies: 'Completion of academic research baseline and initial code modularization.',
      acceptanceCriteria: [
        'Formal architectural specification document approved by technical and security leads.',
        'OpenAPI 3.1 contracts published for ingestion, detection, triage, and management interfaces.',
        'Tenant data isolation specification formally approved prior to SaaS customer onboarding.',
        'Automated CI pipeline operational with static application security testing (SAST) and license audits.'
      ],
      prerequisite: 'Approved API schemas, decoupled service boundaries, tenant isolation blueprint, and threat model.',
    },
    {
      stage: 'Stage 2',
      title: 'Strengthen Existing Capabilities',
      status: 'In Progress / Validated Baseline',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      summary: 'Harden and decouple the four validated problem engines into independently testable services with reproducible benchmarks.',
      objectives: [
        'Decouple detection engines into independent, stateless services with isolated virtual environments.',
        'Establish automated, bit-for-bit reproducible benchmarks across both NSL-KDD and Stratosphere TLS corpora.',
        'Standardize detection evaluation metrics (ROC-AUC, PR-AUC, F1, latency per flow, memory footprint).',
        'Preserve all validated baseline model weights, feature transformers, and threshold tuning scripts.',
        'Conduct targeted rare attack detection research addressing lower recall on R2L and U2R families.',
        'Execute GAN/CTGAN feasibility experiments for synthetic flow generation versus SMOTE baselines.',
        'Conduct adversarial generation and retraining research beyond empirical surrogates.',
        'Advance model explainability across detection (SHAP), anomaly gating, and composite priority scoring.',
        'Initiate concept drift and continual learning experiments without catastrophic forgetting.',
        'Optimise inference performance and latency [Provisional Engineering Target — To Be Validated: sub-5ms CPU model inference latency per flow, distinct from end-to-end pipeline latency; requires formal validation protocol defining hardware/CPU specs, dataset workload, concurrency, and p50/p95/p99 percentiles].',
        'Establish Model Registry & experiment governance tracking weights, feature transformer compatibility, hyperparameters, and artifact lineages.'
      ],
      dependencies: 'Stage 1 architectural contracts, test harness, and evaluation standards.',
      acceptanceCriteria: [
        '100% of existing unit and regression tests pass; bit-for-bit benchmark reproducibility validated.',
        'Sub-5ms single-core CPU model inference latency per flow [Provisional Engineering Target — To Be Validated; distinct from end-to-end pipeline latency].',
        'Zero performance regression on clean attack recall or adversarial evasion mitigation across retraining.',
        'Empirical GAN vs. SMOTE feasibility report completed with leakage and constraint audits.'
      ],
      prerequisite: 'Decoupled service packaging, verified benchmark reproduction scripts, and zero functional regression.',
    },
    {
      stage: 'Stage 3',
      title: 'Core Security Operations Expansion',
      status: 'Planned Engineering',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      summary: 'Build reliable security data ingestion, event normalization, multi-sensor correlation, and incident tracking.',
      objectives: [
        'Implement live network-interface traffic capture (AF_PACKET / DPDK) and PCAP upload processing.',
        'Build reliable bidirectional flow extraction and real-time streaming feature processing.',
        'Deploy streaming inference engine supporting high-throughput flow scoring with backpressure handling.',
        'Implement event normalization and enrichment (OCSF/ECS schemas, GeoIP, ASN lookup).',
        'Introduce multi-sensor alert correlation and temporal deduplication clustering related events into incidents.',
        'Expand incident management: attack timelines, evidence binders, and MITRE ATT&CK mapping.',
        'Threat intelligence lifecycle management: STIX/TAXII 2.1 IOC ingestion, matching, and aging.',
        'Implement initial enterprise Role-Based Access Control (RBAC) and immutable audit logging.'
      ],
      dependencies: 'Stage 2 stabilized detection microservices and persistent database storage.',
      acceptanceCriteria: [
        'Sustained streaming ingestion throughput ≥ 10,000 events/sec with backpressure handling [Provisional Engineering Target — To Be Validated: requires protocol defining hardware/CPU specs, event workload, concurrency, duration, CPU/RAM utilization, and dropped-event rates; distinguished from network wire throughput in Gbps].',
        'Multi-sensor alert correlation achieves ≥ 60% reduction in raw alert volume into grouped incident entities [Provisional Engineering Target — To Be Validated].',
        '100% audit trail logging of all triage modifications and analyst status transitions.',
        'Verified STIX/TAXII 2.1 feed ingestion matching IOCs against active flow telemetry.'
      ],
      prerequisite: 'Validated end-to-end ingestion-to-incident lifecycle with external SIEM/SOAR connector prototypes.',
    },
    {
      stage: 'Stage 4',
      title: 'Enterprise and SaaS Readiness',
      status: 'Planned Engineering',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      summary: 'Enforce multi-tenant data isolation, organization management, secure auth, scalability, encryption, and operational resilience.',
      objectives: [
        'Implement all 10 platform security boundaries: database-level, object storage, cache/queue, API auth, background jobs, model datasets/artifacts, logs/backups, administrative RBAC, secrets management, and tenant auditability.',
        'Implement automated negative authorization test suite verifying zero cross-tenant access across IDOR, API endpoints, background jobs, exports, admin functions, and model retrieval.',
        'Build organization and workspace management supporting multi-team and MSSP deployments.',
        'Deploy secure authentication (SSO via SAML 2.0 / OIDC, MFA) and session management.',
        'Deploy API gateway with scoped keys, rate limiting, and tenant usage quotas.',
        'Develop Infrastructure-as-Code (IaC) deployment automation (Kubernetes Helm charts, Terraform).',
        'Conduct scalability load testing validating horizontal worker autoscaling under peak volumes.',
        'Implement high availability (HA), automated backups, and disaster recovery (DR) playbooks.',
        'Enforce security compliance: data retention policies, cold archival, AES-256 rest / TLS 1.3 transit encryption.',
        'Deploy operational observability: Prometheus metrics endpoints, Grafana dashboards, and tracing.',
        'Establish production Model Registry with canary deployment gates, automated model rollback, and performance drift alerts.',
        'Execute third-party penetration testing, vulnerability assessments, and SOC 2 / ISO 27001 readiness audits.'
      ],
      dependencies: 'Stage 3 SecOps engine and data normalization services.',
      acceptanceCriteria: [
        '99.9% platform availability under synthetic sustained load during 7-day endurance testing [Provisional Engineering Target — To Be Validated].',
        'RTO ≤ 15 minutes and RPO ≤ 5 minutes validated during simulated disaster recovery drills [Provisional Engineering Target — To Be Validated].',
        'Zero High or Critical vulnerabilities in independent third-party penetration testing.',
        'Tenant data isolation verified by automated cross-tenant penetration test harness with zero cross-tenant access findings.'
      ],
      prerequisite: 'SOC 2 Type 1 / ISO 27001 readiness review and production deployment sign-off.',
    },
    {
      stage: 'Stage 5',
      title: 'Governed AI Integration',
      status: 'Long-Term Exploratory Vision',
      badgeClass: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
      summary: 'Augment SecOps workflows with evidence-grounded generative AI assistance under strict human oversight. (Optional parallel workstream that does not block core product experience or pilot preparation).',
      isFuture: true,
      objectives: [
        'Develop AI Security Analyst Assistant for natural-language incident explanations and guidance.',
        'Implement natural-language threat investigation converting questions into optimized queries (Text-to-SQL/ES).',
        'Build automated incident summarisation generating executive handoff reports and shift notes.',
        'Deploy AI-assisted detection rule drafting with sandbox syntax validation (Sigma / YARA-L).',
        'Implement supervised agentic investigation workflows operating strictly under human approval.',
        'Enforce evidence-grounded assistance: AI cannot declare authoritative conclusions without verifiable evidence.',
        'Establish AI Governance Framework: prompt-injection sanitization, tenant-isolated RAG, and audit trails.'
      ],
      dependencies: 'Stage 4 hardened enterprise architecture, RBAC, and contextual incident stores.',
      acceptanceCriteria: [
        'Strict human oversight: 100% of containment actions require affirmative analyst approval.',
        'Prompt-injection defense evaluation achieves ≥ 99% mitigation on standard red-team jailbreaks [Provisional Engineering Target — To Be Validated].',
        'Analyst evaluation demonstrates ≥ 35% reduction in mean time to understand (MTTU) incidents [Provisional Engineering Target — To Be Validated].',
        '100% of AI-generated incident hypotheses are mapped to verifiable telemetry evidence.'
      ],
      prerequisite: 'AI Safety Council certification, model hallucination bounds audit, and red-team sign-off.',
    },
    {
      stage: 'Stage 6',
      title: 'Product Experience and Commercial Validation',
      status: 'Long-Term Exploratory Vision',
      badgeClass: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
      summary: 'Complete enterprise UI/UX redesign, execute design-partner pilot deployments, and validate commercial viability. (UI/UX development, investigation workspaces, usability testing, and pilot onboarding proceed independently of AI assistant capabilities; AI can be integrated in parallel when validated).',
      isFuture: true,
      objectives: [
        'Deliver complete enterprise UI/UX redesign with customizable multi-tenant SOC dashboards (independent of AI integration).',
        'Build interactive attack graph visualizer mapping complex multi-hop cyber kill chains.',
        'Conduct formal usability testing and cognitive walkthroughs with active SOC analysts.',
        'Execute authorized organizational pilot deployments with enterprise security partners.',
        'Onboard multi-tenant pilot organizations with self-service administration and usage tracking.',
        'Empirically measure operational impact: MTTD, MTTR, and analyst triage time reduction.',
        'Finalize commercial SaaS packaging: licensing models, support tiers, and SLA specifications.'
      ],
      dependencies: 'Stage 4 enterprise foundation and tenant isolation, Stage 3 core SecOps workflows, and Stage 2 validated detection models. (Stage 5 Governed AI is an optional parallel workstream that can be integrated when validated, but does not block UI/UX development, usability testing, or core pilot deployments).',
      acceptanceCriteria: [
        'Successful completion of at least 3 authorized pilot deployments in active enterprise SOCs.',
        'Empirically documented ≥ 40% reduction in analyst alert triage time compared to baseline [Provisional Engineering Target — To Be Validated].',
        'Customer Net Promoter Score (NPS) ≥ 50 with commercial pilot conversion readiness [Provisional Engineering Target — To Be Validated].',
        'Commercial packaging, support tiers, and SLA commitments signed off by stakeholders.'
      ],
      prerequisite: 'Pilot evaluation sign-off, commercial pricing model approval, and GA readiness review.',
    },
  ]

  return (
    <div className="space-y-10 animate-fade-in max-w-7xl mx-auto pb-16">
      {/* --------------------------------------------------------------------- */}
      {/* Page Header & Strategic Vision Banner                                 */}
      {/* --------------------------------------------------------------------- */}
      <div className="border-b border-white/8 pb-8 space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-[10px] font-mono uppercase tracking-widest px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                AEGIS Strategic Roadmap
              </span>
              <span className="text-xs font-mono text-cyan-400">6-Stage Lifecycle</span>
              <span className="text-slate-600">·</span>
              <span className="text-xs font-mono text-slate-400">Modules A – H</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
              Intelligent Cybersecurity Operations & Threat Management Platform
            </h1>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <Link
              to="/overview"
              className="text-xs font-mono px-3.5 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 transition-colors flex items-center gap-1.5"
            >
              <span>Live Overview</span>
              <ArrowRight size={13} />
            </Link>
          </div>
        </div>

        {/* Vision Narrative Card */}
        <div className="p-5 rounded-2xl bg-gradient-to-br from-cyan-950/30 via-slate-900/60 to-purple-950/20 border border-cyan-500/20 space-y-3">
          <div className="flex items-center gap-2 text-cyan-300 font-mono text-xs font-bold uppercase tracking-wider">
            <Sparkles size={14} className="text-cyan-400" />
            <span>Strategic Platform Vision & Ecosystem Coexistence</span>
          </div>
          <p className="text-sm text-slate-200 leading-relaxed font-sans">
            AEGIS is evolving from an academic machine learning research prototype into an extensible, intelligent cybersecurity operations and threat management platform. Its mission is to help organizations gain deep security visibility, detect zero-day and encrypted threats, prioritize actionable alerts, investigate incidents, and coordinate response operations without replacing existing enterprise security investments.
          </p>
          <div className="grid md:grid-cols-3 gap-3 pt-2 text-xs text-slate-300">
            <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
              <span className="font-mono text-cyan-400 block font-semibold">Ecosystem Coexistence</span>
              <p className="text-slate-400 leading-snug">Interfaces with enterprise SIEM, SOAR, EDR, and network taps via open APIs rather than demanding rip-and-replace displacement.</p>
            </div>
            <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
              <span className="font-mono text-emerald-400 block font-semibold">Validated Core Bedrock</span>
              <p className="text-slate-400 leading-snug">Builds upon four empirically verified problem engines: zero-day anomaly detection, encrypted TLS inspection, 5-factor triage, and evasion resilience.</p>
            </div>
            <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
              <span className="font-mono text-purple-400 block font-semibold">Multi-Tenant SaaS Evolution</span>
              <p className="text-slate-400 leading-snug">Structured across six sequential development stages transitioning from standalone ML to an enterprise multi-tenant cloud SaaS architecture.</p>
            </div>
          </div>
        </div>

        {/* Status Taxonomy Legend */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
          <span className="text-slate-400 font-mono text-[11px] mr-1">Status Taxonomy:</span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border bg-emerald-500/15 text-emerald-300 border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <strong>Validated Baseline:</strong> Empirically verified algorithms with saved artifacts
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border bg-cyan-500/15 text-cyan-300 border-cyan-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            <strong>Implemented (Partial Baseline):</strong> Working lab baseline; enterprise extensions planned
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border bg-purple-500/15 text-purple-300 border-purple-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
            <strong>Experimental Research:</strong> Active exploratory research (GAN/CTGAN, drift)
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border bg-amber-500/15 text-amber-300 border-amber-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            <strong>Planned Engineering:</strong> Scheduled production engineering & SaaS infrastructure
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
            <strong>Long-Term Vision:</strong> Governed future capabilities & AI integration
          </span>
        </div>

        {/* View Selection Tabs */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-white/5">
          <span className="text-xs font-mono text-slate-500 mr-2">Filter Views:</span>
          <button
            onClick={() => setActiveTab('all')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all ${
              activeTab === 'all'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                : 'bg-white/5 text-slate-400 border border-white/5 hover:bg-white/10'
            }`}
          >
            All Views
          </button>
          <button
            onClick={() => setActiveTab('foundation')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all flex items-center gap-1.5 ${
              activeTab === 'foundation'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm shadow-emerald-500/10'
                : 'bg-white/5 text-slate-400 border border-white/5 hover:bg-white/10'
            }`}
          >
            <span>Foundational Core (P1–P4)</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300">4</span>
          </button>
          <button
            onClick={() => setActiveTab('modules')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all flex items-center gap-1.5 ${
              activeTab === 'modules'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm shadow-amber-500/10'
                : 'bg-white/5 text-slate-400 border border-white/5 hover:bg-white/10'
            }`}
          >
            <span>Functional Modules (A–H)</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300">8</span>
          </button>
          <button
            onClick={() => setActiveTab('stages')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all flex items-center gap-1.5 ${
              activeTab === 'stages'
                ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 shadow-sm shadow-indigo-500/10'
                : 'bg-white/5 text-slate-400 border border-white/5 hover:bg-white/10'
            }`}
          >
            <span>Development Stages (1–6)</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-indigo-500/20 text-indigo-300">6</span>
          </button>
          <button
            onClick={() => setActiveTab('matrix')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all flex items-center gap-1.5 ${
              activeTab === 'matrix'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm shadow-purple-500/10'
                : 'bg-white/5 text-slate-400 border border-white/5 hover:bg-white/10'
            }`}
          >
            <span>Alignment Matrix & Governance</span>
          </button>
        </div>
      </div>

      {/* --------------------------------------------------------------------- */}
      {/* SECTION 1: Foundational Core (The 4 Validated Research Problems)       */}
      {/* --------------------------------------------------------------------- */}
      {(activeTab === 'all' || activeTab === 'foundation') && (
        <ScrollSection className="space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-white/5 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-emerald-400 font-bold uppercase tracking-wider">Foundation Layer</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-slate-400">Four Core Research Problems (P1 – P4)</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                1. Technical Bedrock: Validated Machine Learning Foundations
              </h2>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Verified on NSL-KDD & Stratosphere TLS Holdout Datasets
            </span>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            {foundationalProblems.map((p) => {
              const Icon = p.icon
              return (
                <div
                  key={p.id}
                  className="glass-card p-6 rounded-2xl border border-white/10 space-y-4 hover:border-emerald-500/30 transition-all flex flex-col justify-between"
                >
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          <Icon size={20} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono font-bold text-emerald-400">{p.id}</span>
                            <span className="text-slate-600">·</span>
                            <span className="text-xs font-mono text-slate-400">Validated Baseline</span>
                          </div>
                          <h3 className="text-base font-bold text-white leading-snug">{p.title}</h3>
                        </div>
                      </div>
                      <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full border shrink-0 ${p.badgeClass}`}>
                        {p.status}
                      </span>
                    </div>

                    <p className="text-xs font-mono text-cyan-300/80 leading-relaxed bg-black/30 p-2.5 rounded-lg border border-white/5">
                      {p.subtitle}
                    </p>

                    <p className="text-xs text-slate-300 leading-relaxed font-sans">
                      {p.body}
                    </p>

                    {/* Verified Metrics Grid */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
                      {p.metrics.map((m, i) => (
                        <div key={i} className="p-2.5 rounded-xl bg-black/40 border border-white/5 space-y-0.5">
                          <span className="text-[10px] font-mono text-slate-400 block truncate">{m.label}</span>
                          <span className="text-xs font-mono font-bold text-emerald-400 block">{m.val}</span>
                          <span className="text-[9px] text-slate-400 font-sans leading-tight block">{m.sub}</span>
                        </div>
                      ))}
                    </div>

                    {/* Architecture & Implementation Note */}
                    <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1 text-xs">
                      <div className="flex items-center gap-1.5 text-cyan-300 font-mono text-[11px] font-semibold">
                        <Info size={12} />
                        <span>Implementation Details</span>
                      </div>
                      <p className="text-slate-300 font-sans leading-relaxed text-[11px]">
                        {p.architectureNote}
                      </p>
                    </div>

                    {/* Scope Limitation Warning if present */}
                    {p.scopeLimitation && (
                      <div className="p-3 rounded-xl bg-amber-950/20 border border-amber-500/20 space-y-1 text-xs">
                        <div className="flex items-center gap-1.5 text-amber-300 font-mono text-[11px] font-semibold">
                          <AlertTriangle size={12} />
                          <span>Scope Boundary & Limitation</span>
                        </div>
                        <p className="text-amber-200/80 font-sans leading-relaxed text-[11px]">
                          {p.scopeLimitation}
                        </p>
                      </div>
                    )}

                    {/* Future Research Directions */}
                    <div className="space-y-2 pt-2 border-t border-white/5">
                      <span className="text-[11px] font-mono uppercase tracking-wider text-purple-300 font-semibold block">
                        Planned Research & Extensions
                      </span>
                      <ul className="space-y-1 text-xs text-slate-400">
                        {p.futureResearch.map((item, idx) => (
                          <li key={idx} className="flex items-start gap-1.5 font-sans leading-snug">
                            <ChevronRight size={13} className="text-purple-400 shrink-0 mt-0.5" />
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-white/5 flex items-center justify-between">
                    <span className="text-[11px] font-mono text-slate-400">Interactive Studio:</span>
                    <Link
                      to={p.link}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
                    >
                      <span>{p.linkLabel}</span>
                      <ArrowRight size={12} />
                    </Link>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Research Spotlight: Formal GAN & Generative Research Protocol */}
          <div className="p-6 rounded-2xl bg-gradient-to-br from-purple-950/30 via-slate-900/60 to-black/60 border border-purple-500/20 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-purple-500/20 pb-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
                  <TestTube size={20} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-purple-400 font-bold">Research Protocol</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">P4 Extension Agenda</span>
                  </div>
                  <h3 className="text-base font-bold text-white">
                    Formal GAN / CTGAN Synthetic Traffic & Adversarial Research Methodology
                  </h3>
                </div>
              </div>

              <span className="text-[10px] font-mono px-3 py-1 rounded-full border bg-purple-500/15 text-purple-300 border-purple-500/30 self-start sm:self-auto">
                Experimental Research Direction (Unvalidated)
              </span>
            </div>

            <div className="text-xs text-slate-300 leading-relaxed font-sans space-y-2">
              <p>
                <strong>Current Repository Reality:</strong> The existing implementation in AEGIS applies two-sided numerical Constrained FGSM, Universal Adversarial Perturbations (UAP), and an empirical DEMGAN manifold drift surrogate. <em>No fully trained neural GAN generator exists in the current codebase.</em> DEMGAN in AEGIS is an empirical approximation that drifts mutable numerical features toward benign distribution centroids with calibrated Gaussian jitter under strict protocol clamps. GAN and CTGAN are exploratory research directions, not current production capabilities.
              </p>
              <p className="text-slate-400">
                Future research will execute a rigorous, controlled comparative evaluation to determine whether deep tabular generative models can synthesize high-fidelity network-flow records without violating protocol invariants, inflating false alarms, or memorizing training data.
              </p>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4 pt-1">
              {/* Candidate Approaches */}
              <div className="p-4 rounded-xl bg-black/40 border border-purple-500/20 space-y-2">
                <span className="text-xs font-mono font-bold text-purple-300 block">
                  A. Candidate Approaches
                </span>
                <p className="text-[11px] text-slate-400 leading-snug">
                  Evaluated under identical experimental conditions; GANs will not be assumed superior to simpler methods:
                </p>
                <ul className="space-y-1 text-xs text-slate-300">
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>1. Clean baseline (no augmentation)</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>2. SMOTE (Synthetic Minority Over-sampling)</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>3. ADASYN (Adaptive Synthetic sampling)</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>4. CTGAN (Conditional Tabular GAN)</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>5. WGAN-GP (Wasserstein GAN + Gradient Penalty)</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>6. Heuristic & constrained perturbations (FGSM/DEMGAN)</span></li>
                </ul>
              </div>

              {/* Research Questions */}
              <div className="p-4 rounded-xl bg-black/40 border border-purple-500/20 space-y-2">
                <span className="text-xs font-mono font-bold text-purple-300 block">
                  B. Core Research Questions
                </span>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>Can synthetic samples improve rare family recall (R2L ~45%, U2R ~66%)?</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>Does tabular augmentation improve zero-day generalisation on unseen classes?</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>Does generation preserve multi-feature correlations and physical flow bounds?</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>Do synthetic records produce 100% valid network-flow combinations?</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>Does adversarial synthetic training enhance defense without clean degradation?</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-purple-400 shrink-0 mt-0.5" /><span>Does generative modeling introduce training set memorisation or privacy leakage?</span></li>
                </ul>
              </div>

              {/* Fair Experimental Design */}
              <div className="p-4 rounded-xl bg-black/40 border border-purple-500/20 space-y-2">
                <span className="text-xs font-mono font-bold text-purple-300 block">
                  C. Experimental Hygiene & Design
                </span>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  <li className="flex items-start gap-1.5"><CheckCircle2 size={12} className="text-emerald-400 shrink-0 mt-0.5" /><span><strong>Strict Partitioning:</strong> Preprocessing and generators fit strictly on training splits.</span></li>
                  <li className="flex items-start gap-1.5"><CheckCircle2 size={12} className="text-emerald-400 shrink-0 mt-0.5" /><span><strong>Zero Test Leakage:</strong> Test datasets remain completely untouched during generation.</span></li>
                  <li className="flex items-start gap-1.5"><CheckCircle2 size={12} className="text-emerald-400 shrink-0 mt-0.5" /><span><strong>Identical Baselines:</strong> Equivalent feature sets, hyperparameters, and hardware.</span></li>
                  <li className="flex items-start gap-1.5"><CheckCircle2 size={12} className="text-emerald-400 shrink-0 mt-0.5" /><span><strong>Negative Results Reporting:</strong> Mandatory disclosure of all failures and regressions.</span></li>
                  <li className="flex items-start gap-1.5"><CheckCircle2 size={12} className="text-emerald-400 shrink-0 mt-0.5" /><span><strong>Statistical Rigour:</strong> Paired t-tests, Wilcoxon tests, and 5-seed confidence intervals.</span></li>
                </ul>
              </div>
            </div>

            {/* Evaluation Dimensions & Tentative Goals */}
            <div className="grid md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-black/40 border border-white/5 space-y-2">
                <span className="text-xs font-mono font-bold text-cyan-300 block">
                  D. Multi-Dimensional Evaluation Framework
                </span>
                <div className="grid grid-cols-2 gap-2 text-xs text-slate-300">
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase block">Fidelity & Realism</span>
                    <p className="text-slate-400 text-[11px]">• Wasserstein distance & Jensen-Shannon divergence<br />• Spearman rank correlation matrix preservation<br />• Sample diversity & mode collapse monitoring</p>
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase block">Privacy & Constraints</span>
                    <p className="text-slate-400 text-[11px]">• Nearest-neighbor duplicate distance checks<br />• Membership inference privacy leakage audit<br />• 100% network protocol constraint validity</p>
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase block">Detection Efficacy</span>
                    <p className="text-slate-400 text-[11px]">• Per-class Precision, Recall, F1 (all 5 classes)<br />• Macro-F1 and balanced test accuracy<br />• Zero clean False Positive Rate inflation</p>
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase block">Generalisation</span>
                    <p className="text-slate-400 text-[11px]">• Chronological untouched test holdouts<br />• Family-held-out zero-day evaluation<br />• Multi-seed runs with 95% confidence intervals</p>
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-black/40 border border-white/5 space-y-2">
                <span className="text-xs font-mono font-bold text-emerald-300 block">
                  E. Acceptance Criteria (Desired Experimental Goals — Subject to Validation)
                </span>
                <p className="text-[11px] text-slate-400 leading-snug">
                  These criteria represent desired experimental targets to be empirically validated, not guaranteed outcomes:
                </p>
                <ul className="space-y-1 text-xs text-slate-300">
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-emerald-400 shrink-0 mt-0.5" /><span>Statistically significant improvement in held-out rare attack recall (R2L/U2R) over SMOTE baselines.</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-emerald-400 shrink-0 mt-0.5" /><span>Target zero false-positive-rate inflation on benign operational traffic.</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-emerald-400 shrink-0 mt-0.5" /><span>Target 100% network protocol constraint validity across all generated flow records.</span></li>
                  <li className="flex items-start gap-1.5"><ChevronRight size={12} className="text-emerald-400 shrink-0 mt-0.5" /><span>Target zero training data memorisation or privacy leakage on audit checks.</span></li>
                </ul>
                <div className="p-2 rounded bg-purple-950/30 border border-purple-500/20 text-[10px] font-mono text-purple-200">
                  <strong>Evidence-Based Research Gate:</strong> Adopt deep tabular generative models (CTGAN / WGAN-GP) only if they produce measurable, statistically verified gains over simpler augmentation without compromising data quality, generalisation, or privacy.
                </div>
              </div>
            </div>
          </div>
        </ScrollSection>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* SECTION 2: Long-Term Functional Capability Modules (A through H)       */}
      {/* --------------------------------------------------------------------- */}
      {(activeTab === 'all' || activeTab === 'modules') && (
        <ScrollSection className="space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-white/5 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-amber-400 font-bold uppercase tracking-wider">Functional Architecture</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-slate-400">Modules A through H</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                2. Enterprise Functional Capability Roadmap
              </h2>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Extending Academic Prototypes to Complete SecOps Operations
            </span>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-2 gap-6">
            {functionalModules.map((m) => {
              const Icon = m.icon
              return (
                <div
                  key={m.letter}
                  className="glass-card p-6 rounded-2xl border border-white/10 space-y-4 hover:border-amber-500/30 transition-all flex flex-col justify-between"
                >
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className="p-2.5 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          <Icon size={20} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono font-bold text-amber-400">Module {m.letter}</span>
                            <span className="text-slate-600">·</span>
                            <span className="text-xs font-mono text-slate-400">{m.category}</span>
                          </div>
                          <h3 className="text-base font-bold text-white leading-snug">{m.title}</h3>
                        </div>
                      </div>
                      <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full border shrink-0 ${m.badgeClass}`}>
                        {m.status}
                      </span>
                    </div>

                    {/* Current vs Missing Scope Breakdown */}
                    <div className="grid sm:grid-cols-2 gap-2 text-xs pt-1">
                      <div className="p-2.5 rounded-xl bg-emerald-950/20 border border-emerald-500/20 space-y-1">
                        <div className="flex items-center gap-1.5 text-emerald-400 font-mono text-[11px] font-semibold">
                          <CheckCircle2 size={12} />
                          <span>Current Verified Reality</span>
                        </div>
                        <p className="text-slate-300 font-sans text-[11px] leading-snug">{m.currentVerified}</p>
                      </div>

                      <div className="p-2.5 rounded-xl bg-amber-950/20 border border-amber-500/20 space-y-1">
                        <div className="flex items-center gap-1.5 text-amber-400 font-mono text-[11px] font-semibold">
                          <AlertTriangle size={12} />
                          <span>Missing / Planned Work</span>
                        </div>
                        <p className="text-amber-200/80 font-sans text-[11px] leading-snug">{m.missingWork}</p>
                      </div>
                    </div>

                    {/* Detailed Functional Scope Items */}
                    <div className="space-y-2 pt-2 border-t border-white/5">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                          Planned Functional Capabilities
                        </span>
                        <span className="text-[10px] font-mono text-cyan-400">
                          Target: {m.targetStage}
                        </span>
                      </div>
                      <ul className="space-y-1 text-xs text-slate-300">
                        {m.scope.map((item, idx) => (
                          <li key={idx} className="flex items-start gap-1.5 font-sans leading-snug">
                            <ChevronRight size={13} className="text-amber-400 shrink-0 mt-0.5" />
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {m.isFuture && (
                    <div className="p-2.5 rounded-lg bg-indigo-950/30 border border-indigo-500/20 text-[11px] font-mono text-indigo-300 flex items-center gap-2">
                      <Sparkles size={13} className="text-indigo-400 shrink-0" />
                      <span>Forward-Looking Capability — Not Active in Current Production Release</span>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </ScrollSection>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* SECTION 3: Sequential Development Stages (Stages 1 through 6)          */}
      {/* --------------------------------------------------------------------- */}
      {(activeTab === 'all' || activeTab === 'stages') && (
        <ScrollSection className="space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-white/5 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">Sequential Execution Lifecycle</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-indigo-400 font-bold uppercase tracking-wider">Phased Evolution</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                3. Sequential Development Lifecycle (Stages 1 – 6)
              </h2>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <span>Progression:</span>
              <span className="text-indigo-400 font-bold">Stage 1 → Stage 6</span>
            </div>
          </div>

          <div className="space-y-6">
            {developmentStages.map((s, idx) => (
              <div
                key={s.stage}
                className="glass-card p-6 rounded-2xl border border-white/10 space-y-4 hover:border-indigo-500/30 transition-all relative overflow-hidden"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/5 pb-4">
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono px-3 py-1 rounded-lg bg-white/5 text-white font-bold border border-white/10">
                      {s.stage}
                    </span>
                    <div>
                      <h3 className="text-base font-bold text-white flex items-center gap-2">
                        <span>{s.title}</span>
                      </h3>
                      <p className="text-xs text-slate-400 font-sans">{s.summary}</p>
                    </div>
                  </div>
                  <span className={`text-[10px] font-mono px-3 py-1 rounded-full border self-start sm:self-auto ${s.badgeClass}`}>
                    {s.status}
                  </span>
                </div>

                <div className="grid md:grid-cols-2 gap-6 pt-1">
                  {/* Objectives */}
                  <div className="space-y-2">
                    <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider block">
                      Core Engineering Objectives
                    </span>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {s.objectives.map((obj, i) => (
                        <li key={i} className="flex items-start gap-2 font-sans leading-snug">
                          <ChevronRight size={13} className="text-indigo-400 shrink-0 mt-0.5" />
                          <span>{obj}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Measurable Acceptance Criteria & Prereqs */}
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <span className="text-xs font-mono font-bold text-emerald-300 uppercase tracking-wider block">
                        Measurable Acceptance Criteria
                      </span>
                      <ul className="space-y-1.5 text-xs text-slate-300">
                        {s.acceptanceCriteria.map((crit, i) => (
                          <li key={i} className="flex items-start gap-2 font-sans leading-snug">
                            <CheckCircle2 size={13} className="text-emerald-400 shrink-0 mt-0.5" />
                            <span>{crit}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-2 text-xs">
                      <div>
                        <span className="font-mono text-slate-400 text-[10px] uppercase block">Dependencies</span>
                        <span className="text-slate-300 font-sans text-[11px]">{s.dependencies}</span>
                      </div>
                      <div className="border-t border-white/5 pt-1.5">
                        <span className="font-mono text-cyan-400 text-[10px] uppercase block">Stage Exit Prerequisite</span>
                        <span className="text-cyan-200/90 font-sans text-[11px]">{s.prerequisite}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Connection Line indicator between stages */}
                {idx < developmentStages.length - 1 && (
                  <div className="hidden lg:block absolute -bottom-3 left-1/2 transform -translate-x-1/2 w-6 h-6 rounded-full bg-slate-900 border border-white/20 text-center text-slate-400 text-[10px] leading-5">
                    ↓
                  </div>
                )}
              </div>
            ))}
          </div>
        </ScrollSection>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* SECTION 4: Capability & Stage Alignment Matrix                        */}
      {/* --------------------------------------------------------------------- */}
      {(activeTab === 'all' || activeTab === 'matrix') && (
        <ScrollSection className="space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-white/5 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-purple-400 font-bold uppercase tracking-wider">Traceability & Dependencies Matrix</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-slate-400">Architecture Governance</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                4. Capability & Development Stage Alignment Matrix
              </h2>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Cross-Mapping Modules A–H across Stages 1–6
            </span>
          </div>

          <div className="space-y-6">
            <div className="p-4 rounded-xl bg-black/40 border border-white/10 text-xs text-slate-300 space-y-2 font-sans">
              <div className="flex items-center gap-2 text-purple-300 font-mono font-bold">
                <Shield size={14} />
                <span>Governance & Traceability Statement</span>
              </div>
              <p>
                This matrix maps every functional capability module (A through H) to its validated baseline artifacts, targeted engineering stages, external dependencies, and measurable exit criteria. It enforces non-negotiable architectural boundaries, prevents scope leakage, labels provisional engineering targets subject to future empirical validation, and verifies that no planned feature is represented as already implemented.
              </p>
            </div>

            <div className="glass-card overflow-hidden border border-white/10">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-white/10 bg-black/40 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                      <th className="p-3.5 pl-5">Module</th>
                      <th className="p-3.5">Current Verified Implementation</th>
                      <th className="p-3.5">Remaining Work / Missing Scope</th>
                      <th className="p-3.5">Target Stage</th>
                      <th className="p-3.5">Dependencies</th>
                      <th className="p-3.5 pr-5">Acceptance Criteria</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 font-mono">
                    <tr className="hover:bg-white/5 transition-colors">
                      <td className="p-3.5 pl-5 font-bold text-white">A. Data Collection & Ingestion</td>
                      <td className="p-3.5 text-slate-400">Offline CSV ingestion & synthetic flow presets</td>
                      <td className="p-3.5 text-slate-300 font-sans">Live NIC capture, PCAP parsing, NetFlow/IPFIX, Syslog/EVTX, OCSF normalization, data retention</td>
                      <td className="p-3.5 text-cyan-400">Stage 3 & 4</td>
                      <td className="p-3.5 text-slate-400 font-sans">Network driver bindings, message broker (Kafka)</td>
                      <td className="p-3.5 pr-5 text-emerald-400 font-sans">≥ 10,000 events/sec sustained ingestion [Provisional Engineering Target — To Be Validated; protocol defines CPU/RAM, workload, concurrency, drop rates vs. Gbps line speed]</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors bg-emerald-500/5">
                      <td className="p-3.5 pl-5 font-bold text-white">B. Threat Detection & Analytics</td>
                      <td className="p-3.5 text-emerald-400">P1 MLPRegressor bottleneck reconstruction network + XGBoost hybrid detector, P2 Encrypted Flow XGBoost, P4 Retrained Hardened XGBoost</td>
                      <td className="p-3.5 text-slate-300 font-sans">Model intelligence & lifecycle management (registry, monitoring, drift, controlled retraining), GAN/CTGAN research, R2L/U2R rare attack detection, UEBA, STIX/TAXII threat intel, Sigma rules</td>
                      <td className="p-3.5 text-emerald-400">Stage 2 & 3</td>
                      <td className="p-3.5 text-slate-400 font-sans">Decoupled ML services, feature transformer contracts</td>
                      <td className="p-3.5 pr-5 text-emerald-400 font-sans">Sub-5ms model inference latency per flow [Provisional Engineering Target — To Be Validated; distinct from end-to-end latency]; zero regression on clean recall</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors bg-emerald-500/5">
                      <td className="p-3.5 pl-5 font-bold text-white">C. Alert Intelligence & Prioritisation</td>
                      <td className="p-3.5 text-emerald-400">P3 5-factor composite priority with Critical, Review, Auto-log tiers and Review floor</td>
                      <td className="p-3.5 text-slate-300 font-sans">Cross-sensor correlation, temporal deduplication, incident-level scoring, CMDB asset sync, alert lifecycle state machine</td>
                      <td className="p-3.5 text-emerald-400">Stage 2 & 3</td>
                      <td className="p-3.5 text-slate-400 font-sans">Persistent alert index, CMDB API bindings</td>
                      <td className="p-3.5 pr-5 text-emerald-400 font-sans">≥ 60% alert noise reduction into correlated incidents [Provisional Target — To Be Validated]; 100% triage audit trail</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors">
                      <td className="p-3.5 pl-5 font-bold text-white">D. Investigation & Incident Management</td>
                      <td className="p-3.5 text-slate-400">Incident triage queue & SHAP feature breakdown</td>
                      <td className="p-3.5 text-slate-300 font-sans">Incident grouping, attack timelines, MITRE ATT&CK mapping, cryptographic evidence binders, compliance reporting</td>
                      <td className="p-3.5 text-cyan-400">Stage 3 & 4</td>
                      <td className="p-3.5 text-slate-400 font-sans">Correlated incident store, MITRE ATT&CK STIX ontology</td>
                      <td className="p-3.5 pr-5 text-emerald-400 font-sans">Complete kill-chain visualization; exportable NIST CSF / ISO audit reports</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors">
                      <td className="p-3.5 pl-5 font-bold text-white">E. Response & Security Automation</td>
                      <td className="p-3.5 text-slate-400">Triage tier recommendations & manual preset replay</td>
                      <td className="p-3.5 text-slate-300 font-sans">Visual response playbooks, ticketing dispatch (ServiceNow/Jira), SOAR connectors, mandatory human authorization</td>
                      <td className="p-3.5 text-cyan-400">Stage 3 & 4</td>
                      <td className="p-3.5 text-slate-400 font-sans">Ticketing REST APIs, SOAR webhook connectors</td>
                      <td className="p-3.5 pr-5 text-emerald-400 font-sans">Zero autonomous destructive actions; 100% analyst sign-off compliance</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors">
                      <td className="p-3.5 pl-5 font-bold text-white">F. Enterprise Management & SaaS Governance</td>
                      <td className="p-3.5 text-slate-400">Health liveness check & DB connection telemetry</td>
                      <td className="p-3.5 text-slate-300 font-sans">Platform security & tenant trust (10 isolation boundaries: DB, storage, queue, API, workers, models, logs, admin, Vault secrets, audit), automated negative authorization testing, SSO/MFA, RBAC, API quotas, HA/DR</td>
                      <td className="p-3.5 text-cyan-400">Stage 1 & 4</td>
                      <td className="p-3.5 text-slate-400 font-sans">Identity provider (OIDC/SAML), Vault KMS, cloud IaC</td>
                      <td className="p-3.5 pr-5 text-emerald-400 font-sans">99.9% availability [Provisional Engineering Target — To Be Validated]; verified zero cross-tenant leakage via negative authorization suite; RTO ≤ 15m / RPO ≤ 5m [Provisional Engineering Target — To Be Validated]</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors bg-indigo-500/5">
                      <td className="p-3.5 pl-5 font-bold text-white">G. Future AI-Powered Capabilities</td>
                      <td className="p-3.5 text-slate-400">SHAP tree explanations & reconstruction error shares</td>
                      <td className="p-3.5 text-slate-300 font-sans">AI security chatbot, natural-language threat queries, incident summarisation, AI rule generation, AI governance & guardrails</td>
                      <td className="p-3.5 text-indigo-400">Stage 5</td>
                      <td className="p-3.5 text-slate-400 font-sans">Enterprise RBAC, contextual incident data store, LLM gateway</td>
                      <td className="p-3.5 pr-5 text-indigo-300 font-sans">≥ 99% prompt-injection defense rate [Provisional Target]; ≥ 35% reduction in analyst MTTU [Provisional Target]; 100% human sign-off</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors bg-purple-500/5">
                      <td className="p-3.5 pl-5 font-bold text-white">H. Future Product Experience</td>
                      <td className="p-3.5 text-slate-400">React + Vite + Tailwind SOC dashboard v2.4</td>
                      <td className="p-3.5 text-slate-300 font-sans">Tenant-specific dashboards, customizable widgets, streaming alert monitors, interactive attack graphs, forensic workbench</td>
                      <td className="p-3.5 text-purple-400">Stage 6</td>
                      <td className="p-3.5 text-slate-400 font-sans">Stage 4 multi-tenancy & tenant isolation, Stage 3 streaming pipelines, Stage 2 detection models (Stage 5 AI is an optional parallel track)</td>
                      <td className="p-3.5 pr-5 text-purple-300 font-sans">≥ 3 authorized pilot deployments; ≥ 40% reduction in triage time [Provisional Target — To Be Validated]; NPS ≥ 50 [Provisional Target — To Be Validated]</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Cross-Cutting Architectural Principles */}
            <div className="space-y-4 pt-4 border-t border-white/5">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider">Architectural Foundations</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-slate-400">Cross-Cutting Engineering Principles</span>
              </div>
              <h3 className="text-base font-bold text-white">
                Platform-Wide Cross-Cutting Architectural Principles
              </h3>

              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                {/* 1. Model Intelligence & Lifecycle Management */}
                <div className="p-4 rounded-xl bg-black/30 border border-cyan-500/20 space-y-2.5">
                  <div className="flex items-center gap-2 text-cyan-400 font-mono font-bold text-xs">
                    <Boxes size={14} />
                    <span>Model Intelligence & Lifecycle Management</span>
                  </div>
                  <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                    A platform-wide capability governing model operations beyond static weights. Covers five comprehensive lifecycle pillars:
                  </p>
                  <ul className="space-y-1 text-[11px] text-slate-400 font-sans">
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-cyan-400 shrink-0 mt-0.5" /><span><strong>A. Dataset & Experiment Governance:</strong> Versioning, quality validation, train/test isolation, and leakage auditability.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-cyan-400 shrink-0 mt-0.5" /><span><strong>B. Model Registry & Versioning:</strong> Artifact tracking, feature transformer compatibility, and deployment history.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-cyan-400 shrink-0 mt-0.5" /><span><strong>C. Performance Monitoring:</strong> Per-family F1, FPR/FNR trends, concept drift, and confidence calibration.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-cyan-400 shrink-0 mt-0.5" /><span><strong>D. Controlled Retraining:</strong> Baseline regression tests, rare attack checks, and mandatory human approval.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-cyan-400 shrink-0 mt-0.5" /><span><strong>E. Deployment & Recovery:</strong> Canary rollouts, automated rollback, reproducible restoration, and audit trails.</span></li>
                  </ul>
                  <div className="p-2 rounded bg-cyan-950/30 border border-cyan-500/20 text-[10px] font-mono text-cyan-300">
                    Status: Baseline evaluation scripts verified; enterprise registry & automated drift governance scheduled for Stage 2 & 4.
                  </div>
                </div>

                {/* 2. Platform Security and Tenant Trust */}
                <div className="p-4 rounded-xl bg-black/30 border border-purple-500/20 space-y-2.5">
                  <div className="flex items-center gap-2 text-purple-400 font-mono font-bold text-xs">
                    <ShieldCheck size={14} />
                    <span>Platform Security & Tenant Trust</span>
                  </div>
                  <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                    Non-negotiable security boundaries enforcing strict multi-tenant isolation across ten architectural vectors:
                  </p>
                  <ul className="space-y-1 text-[11px] text-slate-400 font-sans">
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>1. DB Isolation:</strong> Schema-per-tenant or row-level security with enforced tenant scoping.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>2. Storage Isolation:</strong> Isolated evidence buckets and tenant-specific KMS keys.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>3. Queue Isolation:</strong> Partitioned Kafka topics and tenant-prefixed Redis keys.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>4. API Authorization:</strong> JWT tenant claims validation on every API endpoint.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>5. Worker Isolation:</strong> Tenant-aware asynchronous background task workers.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>6. Model Isolation:</strong> Isolated fine-tuning datasets and private model artifacts.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>7. Log & Backup Isolation:</strong> Segregated tenant audit trails and backup archives.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>8. Admin RBAC:</strong> Strict separation of platform vs. tenant administrator roles.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>9. Secrets Management:</strong> HashiCorp Vault envelope encryption and rotation.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>10. Tenant Auditability:</strong> Tamper-evident immutable audit logs per tenant.</span></li>
                  </ul>
                  <div className="p-2 rounded bg-purple-950/30 border border-purple-500/20 text-[10px] font-mono text-purple-200">
                    <strong>Negative Authorization Testing:</strong> Automated test suite verifying cross-tenant access denial across IDOR, APIs, workers, exports, and model retrieval.
                  </div>
                </div>

                {/* 3. Performance Target Governance & Validation Protocol */}
                <div className="p-4 rounded-xl bg-black/30 border border-amber-500/20 space-y-2.5">
                  <div className="flex items-center gap-2 text-amber-400 font-mono font-bold text-xs">
                    <Scale size={14} />
                    <span>Performance Target Governance</span>
                  </div>
                  <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                    All engineering goals are designated as <strong>Provisional Engineering Targets — To Be Validated</strong>. Formal empirical validation requires an explicit 8-parameter benchmarking protocol:
                  </p>
                  <ul className="space-y-1 text-[11px] text-slate-400 font-sans">
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span><strong>1. Hardware Specification:</strong> Explicit CPU model, core allocation, and RAM.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span><strong>2. Workload Definition:</strong> Dataset composition and traffic distribution.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span><strong>3. Concurrency & Traffic Characteristics:</strong> Concurrent connection volume and flow rates.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span><strong>4. Sustained Measurement Duration:</strong> Continuous soak duration validating stability.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span><strong>5. Throughput Methodology:</strong> Distinguish ingestion events/sec from network wire rate in Gbps.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span><strong>6. Latency Percentiles:</strong> p50, p95, and p99; distinguish model inference from end-to-end latency.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span><strong>7. Resource Utilization:</strong> Sustained CPU utilisation and memory RSS footprint.</span></li>
                    <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span><strong>8. Reliability:</strong> Measured dropped-event and error rates under peak load.</span></li>
                  </ul>
                  <div className="p-2 rounded bg-amber-950/30 border border-amber-500/20 text-[10px] font-mono text-amber-300">
                    Targets (sub-5ms CPU, ≥10k events/s, 10 Gbps, 99.9% uptime, RTO/RPO) are engineering aspirations subject to rigorous future benchmark validation.
                  </div>
                </div>

                {/* 4. Cross-Cutting Explainability */}
                <div className="p-4 rounded-xl bg-black/30 border border-emerald-500/20 space-y-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-mono font-bold text-xs">
                    <Sliders size={14} />
                    <span>Cross-Cutting Explainability</span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed font-sans">
                    Explainability is a cross-cutting architecture principle across all platform tiers: tree SHAP values for known threat families, reconstruction error decomposition for novel zero-days, 5-term priority attribution for triage, and chronological kill-chain timelines for incident forensics.
                  </p>
                </div>

                {/* 5. Guardrailed Human Approval */}
                <div className="p-4 rounded-xl bg-black/30 border border-red-500/20 space-y-2">
                  <div className="flex items-center gap-2 text-red-400 font-mono font-bold text-xs">
                    <Workflow size={14} />
                    <span>Guardrailed Human Approval</span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed font-sans">
                    All active containment, firewall rule updates, endpoint isolation, and detection rule modifications require explicit, authenticated analyst authorization. Autonomous destructive blocking is strictly excluded from platform architecture.
                  </p>
                </div>

                {/* 6. Ecosystem Interoperability */}
                <div className="p-4 rounded-xl bg-black/30 border border-blue-500/20 space-y-2">
                  <div className="flex items-center gap-2 text-blue-400 font-mono font-bold text-xs">
                    <GitFork size={14} />
                    <span>Open Standards & Interoperability</span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed font-sans">
                    Built for ecosystem coexistence using open cybersecurity standards: OCSF/ECS event schemas, STIX/TAXII 2.1 threat intelligence feeds, Sigma/YARA-L detection rules, and OpenAPI 3.1 microservice contracts.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </ScrollSection>
      )}
    </div>
  )
}
