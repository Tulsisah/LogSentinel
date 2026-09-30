import { useState, useEffect, useCallback } from 'react';
import { getHistory, deleteSession } from '../services/api';
import { 
  History, 
  Trash2, 
  ExternalLink, 
  FileCode, 
  ShieldAlert, 
  Activity, 
  Database
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const HistoryView = () => {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const fetchHistory = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getHistory();
      setSessions(data);
    } catch (err) {
      console.error('Failed to load history', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const handleDeleteSession = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this historical analysis session? Associated logs and alerts will be removed.')) return;
    try {
      await deleteSession(id);
      setSessions(sessions.filter(s => s.id !== id));
    } catch (err) {
      console.error('Failed to delete session', err);
    }
  };

  const handleOpenSession = (session) => {
    // Navigate to log explorer filtered by this session id or file name
    navigate(`/logs?search=${encodeURIComponent(session.filename || '')}`);
  };

  const totalLogs = sessions.reduce((acc, s) => acc + (s.log_count || 0), 0);
  const totalThreats = sessions.reduce((acc, s) => acc + (s.threat_count || 0), 0);

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-primary/10 border border-primary/20 rounded-xl text-primary">
              <History className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-text-main">Analysis Session History</h2>
              <p className="text-text-muted text-sm mt-0.5">
                Audit trail of past log ingestion batches, detection metrics, and forensic sessions.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-surface border border-surface-light rounded-2xl p-4 flex items-center gap-4">
          <div className="p-3 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Database className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-text-muted uppercase font-semibold">Total Sessions</div>
            <div className="text-2xl font-black text-text-main mt-0.5">{sessions.length}</div>
          </div>
        </div>

        <div className="bg-surface border border-surface-light rounded-2xl p-4 flex items-center gap-4">
          <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-text-muted uppercase font-semibold">Total Logs Ingested</div>
            <div className="text-2xl font-black text-text-main mt-0.5">{totalLogs.toLocaleString()}</div>
          </div>
        </div>

        <div className="bg-surface border border-surface-light rounded-2xl p-4 flex items-center gap-4">
          <div className="p-3 rounded-xl bg-danger/10 text-danger border border-danger/20">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-text-muted uppercase font-semibold">Total Threats Detected</div>
            <div className="text-2xl font-black text-danger mt-0.5">{totalThreats}</div>
          </div>
        </div>
      </div>

      {/* Session Table */}
      <div className="bg-surface rounded-2xl border border-surface-light overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-light/40 border-b border-surface-light text-text-muted text-xs uppercase tracking-wider">
                <th className="px-4 py-4 font-medium text-center w-14">S.No.</th>
                <th className="px-6 py-4 font-medium">Session ID & File</th>
                <th className="px-6 py-4 font-medium">Timestamp</th>
                <th className="px-6 py-4 font-medium">Log Count</th>
                <th className="px-6 py-4 font-medium">Threat Count</th>
                <th className="px-6 py-4 font-medium">Critical Threats</th>
                <th className="px-6 py-4 font-medium">Risk Score</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-light">
              {loading ? (
                <tr>
                  <td colSpan="8" className="px-6 py-12 text-center text-text-muted animate-pulse">
                    Loading historical analysis sessions...
                  </td>
                </tr>
              ) : sessions.length === 0 ? (
                <tr>
                  <td colSpan="8" className="px-6 py-12 text-center text-text-muted">
                    <History className="w-10 h-10 mx-auto mb-3 text-surface-light" />
                    <p className="text-base font-medium">No past sessions recorded yet</p>
                    <p className="text-xs text-text-muted mt-1">
                      Uploaded files and sample logs will appear here for historical correlation.
                    </p>
                  </td>
                </tr>
              ) : (
                sessions.map((session, idx) => (
                  <tr 
                    key={session.id}
                    onClick={() => handleOpenSession(session)}
                    className="hover:bg-surface-light/30 transition-colors cursor-pointer group"
                  >
                    <td className="px-4 py-4 text-center text-text-muted font-mono text-xs font-medium">
                      {idx + 1}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2.5">
                        <FileCode className="w-4 h-4 text-primary shrink-0" />
                        <div>
                          <div className="font-bold text-sm text-text-main group-hover:text-primary transition-colors">
                            {session.filename || 'Pasted Log Buffer'}
                          </div>
                          <div className="text-[11px] font-mono text-text-muted">ID: {session.id}</div>
                        </div>
                      </div>
                    </td>

                    <td className="px-6 py-4 text-xs text-text-muted font-mono whitespace-nowrap">
                      {new Date(session.created_at || session.timestamp).toLocaleString()}
                    </td>

                    <td className="px-6 py-4 text-sm font-semibold text-text-main">
                      {session.log_count?.toLocaleString() || 0}
                    </td>

                    <td className="px-6 py-4">
                      <span className={`text-xs font-bold px-2.5 py-1 rounded-md ${
                        session.threat_count > 0 
                          ? 'bg-warning/15 text-warning border border-warning/30' 
                          : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {session.threat_count} threats
                      </span>
                    </td>

                    <td className="px-6 py-4">
                      <span className={`text-xs font-bold ${(session.critical_count ?? session.critical_threats ?? 0) > 0 ? 'text-danger' : 'text-text-muted'}`}>
                        {session.critical_count ?? session.critical_threats ?? 0}
                      </span>
                    </td>

                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-14 h-1.5 bg-background rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              session.risk_score >= 70 ? 'bg-danger' :
                              session.risk_score >= 40 ? 'bg-warning' :
                              'bg-primary'
                            }`}
                            style={{ width: `${Math.min(session.risk_score || 0, 100)}%` }}
                          />
                        </div>
                        <span className="text-xs font-bold">{Math.round(session.risk_score || 0)}</span>
                      </div>
                    </td>

                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => handleOpenSession(session)}
                          className="px-2.5 py-1.5 rounded-lg bg-surface-light hover:bg-primary/10 hover:text-primary text-xs font-semibold transition-colors flex items-center gap-1"
                          title="Open in Log Explorer"
                        >
                          Explore <ExternalLink className="w-3 h-3" />
                        </button>
                        <button
                          onClick={(e) => handleDeleteSession(session.id, e)}
                          className="p-1.5 rounded-lg text-text-muted hover:text-danger hover:bg-danger/10 transition-colors"
                          title="Delete Session"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default HistoryView;
