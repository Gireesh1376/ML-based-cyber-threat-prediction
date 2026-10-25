import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import './index.css'
import App from './App.tsx'
import Landing from './pages/Landing.tsx'
import Overview from './pages/Overview.tsx'
import ZeroDayLab from './pages/ZeroDayLab.tsx'
import Alerts from './pages/Alerts.tsx'
import Model from './pages/Model.tsx'
import Roadmap from './pages/Roadmap.tsx'
import AdversarialLab from './pages/AdversarialLab.tsx'
import EncryptedLab from './pages/EncryptedLab.tsx'

import { ThemeProvider } from './context/ThemeContext.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<App />}>
            <Route path="/" element={<Landing />} />
            <Route path="/overview" element={<Overview />} />
            <Route path="/zero-day" element={<ZeroDayLab />} />
            <Route path="/encrypted" element={<EncryptedLab />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/adversarial" element={<AdversarialLab />} />
            <Route path="/model" element={<Model />} />
            <Route path="/roadmap" element={<Roadmap />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  </StrictMode>,
)
