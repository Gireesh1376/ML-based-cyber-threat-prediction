import { useState, useEffect } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { 
  Activity, 
  BellRing, 
  Cpu, 
  LayoutDashboard, 
  Radar, 
  ShieldCheck, 
  PanelLeftClose, 
  PanelLeftOpen, 
  Home, 
  Zap,
  SunMedium,
  Moon
} from 'lucide-react'
import { useTheme } from './context/ThemeContext'

const navigationItems = [
  { to: '/', label: 'Executive Hub', icon: Home, end: true, badge: null },
  { to: '/overview', label: 'Threat Operations', icon: LayoutDashboard, end: false, badge: 'Live' },
  { to: '/alerts', label: 'Incident Triage', icon: BellRing, end: false, badge: 'Queue' },
  { to: '/zero-day', label: 'Zero-Day Studio', icon: Radar, end: false, badge: 'Lab' },
  { to: '/model', label: 'Model Intelligence', icon: Cpu, end: false, badge: '87.5%' },
  { to: '/roadmap', label: 'Program Roadmap', icon: ShieldCheck, end: false, badge: '4-Tier' },
]

export default function App() {
  const { theme, toggleTheme } = useTheme()
  const [collapsed, setCollapsed] = useState(false)
  const location = useLocation()

  // Keyboard shortcut: Press `[` or `\` to toggle sidebar
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.key === '[' || e.key === '\\') && !e.ctrlKey && !e.metaKey && e.target instanceof HTMLElement && e.target.tagName !== 'INPUT') {
        e.preventDefault()
        setCollapsed((prev) => !prev)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  const currentNav = navigationItems.find((item) => 
    item.end ? location.pathname === item.to : location.pathname.startsWith(item.to)
  )

  return (
    <div className="min-h-screen flex bg-[#070b12] text-slate-100 font-sans selection:bg-emerald-500/20 selection:text-emerald-300 antialiased">
      {/* Animated Collapsible Sidebar */}
      <aside 
        className={`shrink-0 border-r border-white/8 glass-panel z-30 transition-all duration-300 ease-[cubic-bezier(0.2,0.8,0.2,1)] flex flex-col relative ${
          collapsed ? 'w-20' : 'w-64'
        }`}
      >
        {/* Brand Header */}
        <div className={`h-16 flex items-center border-b border-white/8 relative overflow-hidden transition-all duration-300 ${
          collapsed ? 'justify-center px-0' : 'justify-between px-4'
        }`}>
          {!collapsed ? (
            <>
              <div className="flex items-center gap-3 overflow-hidden min-w-0">
                <div className="h-9 w-9 shrink-0 rounded-xl bg-gradient-to-br from-emerald-400 to-teal-600 text-slate-950 grid place-items-center shadow-md shadow-emerald-500/20">
                  <Activity size={20} className="stroke-[2.5]" />
                </div>
                
                <div className="flex flex-col whitespace-nowrap">
                  <span className="font-bold text-sm tracking-wide text-white leading-tight">AEGIS SOC</span>
                  <span className="text-[10px] font-medium text-emerald-400 tracking-wider uppercase">Defense AI</span>
                </div>
              </div>

              <button
                onClick={() => setCollapsed(true)}
                aria-label="Collapse sidebar"
                title="Collapse sidebar (Hotkey: [)"
                className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-white/10 transition-all duration-200 active:scale-90"
              >
                <PanelLeftClose size={18} />
              </button>
            </>
          ) : (
            <button
              onClick={() => setCollapsed(false)}
              aria-label="Expand sidebar"
              title="Expand sidebar (Hotkey: [)"
              className="group relative h-10 w-10 rounded-xl bg-gradient-to-br from-emerald-400 to-teal-600 text-slate-950 grid place-items-center shadow-md shadow-emerald-500/20 hover:scale-105 hover:shadow-emerald-500/40 transition-all duration-200 active:scale-95 cursor-pointer"
            >
              {/* Default Logo Icon */}
              <Activity 
                size={20} 
                className="stroke-[2.5] transition-all duration-200 group-hover:opacity-0 group-hover:scale-75" 
              />
              {/* Hover Expand Icon */}
              <PanelLeftOpen 
                size={20} 
                className="stroke-[2.5] text-slate-950 absolute opacity-0 scale-75 transition-all duration-200 group-hover:opacity-100 group-hover:scale-100" 
              />
            </button>
          )}
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1.5 flex-1 overflow-y-auto">
          {!collapsed && (
            <div className="px-3 pt-2 pb-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-500 animate-fade-in">
              Navigation
            </div>
          )}
          {navigationItems.map(({ to, label, icon: Icon, end, badge }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              title={collapsed ? label : undefined}
              className={({ isActive }) =>
                `group relative flex items-center ${
                  collapsed 
                    ? 'justify-center w-10 h-10 mx-auto p-0' 
                    : 'w-full px-3 py-2.5 gap-3'
                } rounded-xl text-xs font-medium transition-all duration-200 ${
                  isActive
                    ? 'bg-gradient-to-r from-emerald-500/15 via-emerald-500/10 to-teal-500/5 text-emerald-300 border border-emerald-500/25 shadow-sm shadow-emerald-500/10'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-white/5 hover:translate-x-0.5'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {/* Active sliding indicator bar */}
                  {isActive && (
                    <span 
                      className={`absolute top-2 bottom-2 w-1 rounded-r-full bg-emerald-400 shadow-[0_0_12px_#10b981] ${
                        collapsed ? '-left-5' : 'left-0'
                      }`} 
                    />
                  )}

                  <Icon 
                    size={18} 
                    className={`shrink-0 transition-transform duration-200 ${
                      isActive ? 'text-emerald-400 scale-110' : 'group-hover:scale-110'
                    }`} 
                  />

                  {!collapsed && (
                    <div className="flex-1 flex items-center justify-between overflow-hidden animate-fade-in">
                      <span className="truncate">{label}</span>
                      {badge && (
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-md bg-white/5 text-slate-400 border border-white/5 group-hover:border-white/10 group-hover:text-slate-300 transition-colors">
                          {badge}
                        </span>
                      )}
                    </div>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Sidebar Footer Status */}
        <div className="p-3 border-t border-white/8 bg-black/20 space-y-2">
          {!collapsed ? (
            <>
              <div className="space-y-2 p-2.5 rounded-xl bg-slate-900/60 border border-white/5 text-[11px] animate-fade-in">
                <div className="flex items-center justify-between">
                  <span className="text-slate-300 font-medium flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-beacon" />
                    Dual-Model Core
                  </span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                    ONLINE
                  </span>
                </div>
                <div className="text-[10px] text-slate-500 leading-tight">
                  Leave-Family-Out Validation · Zero Data Leakage
                </div>
              </div>

              {/* Sidebar Quick Theme Switcher */}
              <button
                onClick={toggleTheme}
                className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-black/20 hover:bg-white/10 text-[11px] text-slate-400 hover:text-white transition-all cursor-pointer border border-white/5"
                title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode (Shift + T)`}
              >
                <span className="flex items-center gap-1.5">
                  {theme === 'dark' ? <SunMedium size={13} className="text-amber-400" /> : <Moon size={13} className="text-indigo-400" />}
                  <span>{theme === 'dark' ? 'Light Theme' : 'Dark Theme'}</span>
                </span>
                <kbd className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/5 border border-white/10">⇧T</kbd>
              </button>
            </>
          ) : (
            <div className="flex flex-col items-center gap-2 py-1">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-beacon shadow-[0_0_10px_#10b981]" title="Core Engine: Active & Online" />
              <button
                onClick={toggleTheme}
                className="p-1.5 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white transition-colors cursor-pointer"
                title={`Toggle Theme (${theme === 'dark' ? 'Light' : 'Dark'})`}
              >
                {theme === 'dark' ? <SunMedium size={14} className="text-amber-400" /> : <Moon size={14} className="text-indigo-400" />}
              </button>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top App Header */}
        <header className="h-16 shrink-0 border-b border-white/8 glass-panel px-6 flex items-center justify-between z-20 sticky top-0 backdrop-blur-xl">
          <div className="flex items-center gap-3">
            {collapsed && (
              <button
                onClick={() => setCollapsed(false)}
                aria-label="Expand sidebar"
                title="Expand sidebar (Hotkey: [)"
                className="text-slate-400 hover:text-white p-1.5 -ml-2 rounded-lg hover:bg-white/10 transition-colors flex items-center justify-center cursor-pointer"
              >
                <PanelLeftOpen size={18} />
              </button>
            )}
            <span className="text-xs font-medium text-slate-400 hidden sm:inline">Workspace</span>
            <span className="text-slate-600 hidden sm:inline">/</span>
            <span className="text-xs font-semibold text-white tracking-wide">
              {currentNav?.label ?? 'Threat Operations'}
            </span>
          </div>

          <div className="flex items-center gap-3">
            {/* Header Theme Toggle Pill */}
            <button
              onClick={toggleTheme}
              className="flex items-center gap-2 px-3 py-1.5 rounded-full glass-pill text-xs font-medium transition-all duration-200 cursor-pointer hover:scale-105 active:scale-95 group shadow-sm border border-white/10 hover:border-emerald-500/40"
              title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode (Hotkey: Shift + T)`}
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? (
                <>
                  <SunMedium size={14} className="text-amber-400 group-hover:rotate-45 transition-transform duration-300" />
                  <span className="text-slate-300 group-hover:text-white transition-colors">Light Mode</span>
                </>
              ) : (
                <>
                  <Moon size={14} className="text-indigo-500 group-hover:-rotate-12 transition-transform duration-300" />
                  <span className="text-slate-700 group-hover:text-slate-900 transition-colors">Dark Mode</span>
                </>
              )}
            </button>

            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full glass-pill text-xs text-slate-300 hover:border-white/20 transition-colors">
              <Zap size={14} className="text-amber-400" />
              <span>NSL-KDD Benchmark</span>
              <span className="text-slate-600">·</span>
              <span className="font-mono text-emerald-400 font-semibold">87.5% Acc</span>
            </div>

            <div className="flex items-center gap-2 pl-2">
              <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-mono text-slate-400">FastAPI Ready</span>
            </div>
          </div>
        </header>

        {/* Dynamic Outlet with Smooth Page Transition on Route Change */}
        <main className="flex-1 min-w-0 p-6 sm:p-8 overflow-y-auto">
          <div 
            key={location.pathname} 
            className={location.pathname === '/' ? 'animate-landing-fade' : 'animate-fade-in-up'}
          >
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
