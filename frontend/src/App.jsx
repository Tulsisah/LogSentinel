import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Sun, Moon } from 'lucide-react';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import LogExplorer from './components/LogExplorer';
import AlertsList from './components/AlertsList';
import AlertDetails from './components/AlertDetails';
import IncidentsView from './components/IncidentsView';
import IpAnalysisView from './components/IpAnalysisView';
import CustomRulesView from './components/CustomRulesView';
import AiCopilotView from './components/AiCopilotView';
import ReportsView from './components/ReportsView';
import HistoryView from './components/HistoryView';
import LogUploader from './components/LogUploader';

function App() {
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('soc_theme') || 'light';
  });

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('soc_theme', theme);
  }, [theme]);

  return (
    <Router>
      <div className="flex h-screen bg-background text-text-main overflow-hidden">
        <Sidebar />
        <div className="flex-1 flex flex-col overflow-hidden relative">
          <header className="h-16 bg-surface border-b border-surface-light flex items-center justify-between px-6 shrink-0 z-10 shadow-sm print:hidden">
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold bg-gradient-to-r from-emerald-600 to-teal-600 dark:from-emerald-400 dark:to-cyan-400 bg-clip-text text-transparent">
                SOC Analytics & Threat Intelligence Engine
              </h1>
            </div>
            <div className="flex items-center gap-3">
              {/* Theme Mode Toggle (Light #E6FDFF / Dark) */}
              <div className="flex items-center bg-surface-light/40 p-0.5 rounded-full border border-surface-light text-xs">
                <button
                  type="button"
                  onClick={() => setTheme('light')}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-full font-medium transition-all cursor-pointer ${
                    theme === 'light'
                      ? 'bg-background text-emerald-800 shadow-sm font-bold border border-surface-light'
                      : 'text-text-muted hover:text-text-main'
                  }`}
                  title="Light Mode (#E6FDFF)"
                >
                  <Sun className="w-3.5 h-3.5 text-amber-500" />
                  <span>Light</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTheme('dark')}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-full font-medium transition-all cursor-pointer ${
                    theme === 'dark'
                      ? 'bg-surface text-cyan-400 shadow-sm font-bold border border-surface-light'
                      : 'text-text-muted hover:text-text-main'
                  }`}
                  title="Dark Mode"
                >
                  <Moon className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Dark</span>
                </button>
              </div>

              <span className="text-xs bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 px-3 py-1 rounded-full font-mono flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 dark:bg-emerald-400 animate-pulse"></span>
                SOC Live Active
              </span>
            </div>
          </header>
          
          <main className="flex-1 overflow-x-hidden overflow-y-auto bg-background p-6 print:p-0 print:bg-white">
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/logs" element={<LogExplorer />} />
              <Route path="/alerts" element={<AlertsList />} />
              <Route path="/alerts/:id" element={<AlertDetails />} />
              <Route path="/incidents" element={<IncidentsView />} />
              <Route path="/ips" element={<IpAnalysisView />} />
              <Route path="/rules" element={<CustomRulesView />} />
              <Route path="/copilot" element={<AiCopilotView />} />
              <Route path="/reports" element={<ReportsView />} />
              <Route path="/history" element={<HistoryView />} />
              <Route path="/upload" element={<LogUploader />} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
