import { useState, useEffect, useCallback } from 'react';
import { getAlerts, updateAlertStatus, bulkUpdateAlertStatus } from '../services/api';
import { useNavigate, useLocation } from 'react-router-dom';
import { 
  Search, 
  Filter, 
  ChevronRight, 
  ShieldCheck, 
  CheckSquare, 
  Square, 
  CheckCheck 
} from 'lucide-react';

const SeverityBadge = ({ severity }) => {
  const colors = {
    CRITICAL: 'bg-red-500/10 text-red-500 border-red-500/20',
    HIGH: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
    MEDIUM: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
    LOW: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
  };
  
  return (
    <span className={`px-2.5 py-1 rounded-md text-xs font-bold border ${colors[severity] || colors.LOW}`}>
      {severity}
    </span>
  );
};

const AlertsList = () => {
  const location = useLocation();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState(location.state?.filterSeverity || 'ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [selectedAlerts, setSelectedAlerts] = useState([]);
  const navigate = useNavigate();

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getAlerts();
      setAlerts(data);
    } catch (error) {
      console.error('Failed to fetch alerts', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  useEffect(() => {
    if (location.state?.filterSeverity) {
      setFilterSeverity(location.state.filterSeverity);
    }
  }, [location.state]);

  const handleStatusChange = async (e, id, currentStatus) => {
    e.stopPropagation();
    const newStatus = e.target.value;
    if (newStatus === currentStatus) return;
    
    try {
      await updateAlertStatus(id, newStatus);
      // Optimistic update
      setAlerts(alerts.map(a => a.id === id ? { ...a, status: newStatus } : a));
    } catch (error) {
      console.error('Failed to update status', error);
    }
  };

  const handleSelectAll = () => {
    if (selectedAlerts.length === filteredAlerts.length) {
      setSelectedAlerts([]);
    } else {
      setSelectedAlerts(filteredAlerts.map(a => a.id));
    }
  };

  const handleSelectOne = (id, e) => {
    e.stopPropagation();
    if (selectedAlerts.includes(id)) {
      setSelectedAlerts(selectedAlerts.filter(item => item !== id));
    } else {
      setSelectedAlerts([...selectedAlerts, id]);
    }
  };

  const handleBulkStatus = async (newStatus) => {
    if (selectedAlerts.length === 0) return;
    try {
      await bulkUpdateAlertStatus(selectedAlerts, newStatus);
      setAlerts(alerts.map(a => selectedAlerts.includes(a.id) ? { ...a, status: newStatus } : a));
      setSelectedAlerts([]);
    } catch (error) {
      console.error('Bulk update failed', error);
    }
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = 
      alert.source_ip.includes(search) || 
      alert.threat_type.toLowerCase().includes(search.toLowerCase()) ||
      alert.username?.toLowerCase().includes(search.toLowerCase());
      
    const matchesSeverity = filterSeverity === 'ALL' || alert.severity === filterSeverity;
    const matchesStatus = filterStatus === 'ALL' || alert.status === filterStatus;
    
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <div className="space-y-6 pb-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold">Security Alerts</h2>
          <p className="text-text-muted text-sm mt-1">Review and manage detected threats, anomalies, and triage states.</p>
        </div>
        
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
            <input 
              type="text" 
              placeholder="Search IP, Threat, User..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 bg-surface border border-surface-light rounded-xl focus:outline-none focus:border-primary/50 text-sm w-56 transition-colors text-text-main"
            />
          </div>
          
          <div className="relative">
            <Filter className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="pl-9 pr-8 py-2 bg-surface border border-surface-light rounded-xl focus:outline-none focus:border-primary/50 text-sm appearance-none cursor-pointer transition-colors text-text-main"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="relative">
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-4 py-2 bg-surface border border-surface-light rounded-xl focus:outline-none focus:border-primary/50 text-sm appearance-none cursor-pointer transition-colors text-text-main"
            >
              <option value="ALL">All Statuses</option>
              <option value="New">New</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
              <option value="False Positive">False Positive</option>
            </select>
          </div>
        </div>
      </div>

      {/* Bulk Action Toolbar */}
      {selectedAlerts.length > 0 && (
        <div className="bg-primary/10 border border-primary/30 rounded-2xl p-3 px-5 flex flex-wrap items-center justify-between gap-3 animate-fadeIn">
          <div className="flex items-center gap-2 text-xs font-semibold text-text-main">
            <CheckCheck className="w-4 h-4 text-primary" />
            <span>{selectedAlerts.length} alert{selectedAlerts.length > 1 ? 's' : ''} selected</span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted">Bulk Mark As:</span>
            <button
              onClick={() => handleBulkStatus('Investigating')}
              className="px-3 py-1 bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 text-xs font-bold rounded-lg border border-purple-500/30 transition-colors"
            >
              Investigating
            </button>
            <button
              onClick={() => handleBulkStatus('Resolved')}
              className="px-3 py-1 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 text-xs font-bold rounded-lg border border-emerald-500/30 transition-colors"
            >
              Resolved
            </button>
            <button
              onClick={() => handleBulkStatus('False Positive')}
              className="px-3 py-1 bg-surface-light hover:bg-surface-light/80 text-text-muted text-xs font-bold rounded-lg border border-surface-light transition-colors"
            >
              False Positive
            </button>
            <button
              onClick={() => setSelectedAlerts([])}
              className="px-2 py-1 text-xs text-text-muted hover:text-text-main ml-2"
            >
              Clear
            </button>
          </div>
        </div>
      )}

      <div className="bg-surface rounded-2xl border border-surface-light overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-light/50 border-b border-surface-light text-text-muted text-xs uppercase tracking-wider">
                <th className="px-4 py-4 w-10 text-center">
                  <button 
                    onClick={handleSelectAll}
                    className="text-text-muted hover:text-text-main focus:outline-none"
                  >
                    {selectedAlerts.length > 0 && selectedAlerts.length === filteredAlerts.length ? (
                      <CheckSquare className="w-4 h-4 text-primary" />
                    ) : (
                      <Square className="w-4 h-4" />
                    )}
                  </button>
                </th>
                <th className="px-3 py-4 font-medium text-center w-14">S.No.</th>
                <th className="px-4 py-4 font-medium">Timestamp</th>
                <th className="px-4 py-4 font-medium">Severity</th>
                <th className="px-4 py-4 font-medium">Threat Type</th>
                <th className="px-4 py-4 font-medium">Source IP</th>
                <th className="px-4 py-4 font-medium">Risk Score</th>
                <th className="px-4 py-4 font-medium">Status</th>
                <th className="px-4 py-4 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-light">
              {loading ? (
                <tr>
                  <td colSpan="9" className="px-6 py-8 text-center text-text-muted animate-pulse">
                    Loading alerts...
                  </td>
                </tr>
              ) : filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan="9" className="px-6 py-12 text-center text-text-muted">
                    <ShieldCheck className="w-12 h-12 mx-auto mb-3 text-surface-light" />
                    <p className="text-lg font-medium">No alerts found</p>
                    <p className="text-sm">Try adjusting your filters or uploading new logs.</p>
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert, idx) => (
                  <tr 
                    key={alert.id} 
                    onClick={() => navigate(`/alerts/${alert.id}`)}
                    className="hover:bg-surface-light/30 transition-colors cursor-pointer group"
                  >
                    <td className="px-4 py-4 text-center" onClick={(e) => handleSelectOne(alert.id, e)}>
                      {selectedAlerts.includes(alert.id) ? (
                        <CheckSquare className="w-4 h-4 text-primary mx-auto" />
                      ) : (
                        <Square className="w-4 h-4 text-text-muted group-hover:text-text-main mx-auto" />
                      )}
                    </td>
                    <td className="px-3 py-4 text-center text-text-muted font-mono text-xs font-medium">
                      {idx + 1}
                    </td>
                    <td className="px-4 py-4 text-sm text-text-muted whitespace-nowrap">
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-4 py-4">
                      <div className="font-medium text-text-main">{alert.threat_type}</div>
                      <div className="text-xs text-text-muted truncate max-w-xs">{alert.event}</div>
                    </td>
                    <td className="px-4 py-4 text-sm font-mono text-primary-dark">
                      {alert.source_ip}
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-background rounded-full overflow-hidden">
                          <div 
                            className={`h-full ${alert.risk_score > 79 ? 'bg-danger' : alert.risk_score > 59 ? 'bg-warning' : alert.risk_score > 29 ? 'bg-yellow-500' : 'bg-primary'}`} 
                            style={{ width: `${alert.risk_score}%` }}
                          />
                        </div>
                        <span className="text-xs font-bold">{Math.round(alert.risk_score)}</span>
                      </div>
                    </td>
                    <td className="px-4 py-4" onClick={e => e.stopPropagation()}>
                      <select 
                        value={alert.status}
                        onChange={(e) => handleStatusChange(e, alert.id, alert.status)}
                        className="bg-transparent border-none text-sm focus:outline-none cursor-pointer appearance-none px-2 py-1 -ml-2 rounded hover:bg-surface-light text-text-main"
                      >
                        <option className="bg-surface text-text-main" value="New">New</option>
                        <option className="bg-surface text-text-main" value="Investigating">Investigating</option>
                        <option className="bg-surface text-text-main" value="Resolved">Resolved</option>
                        <option className="bg-surface text-text-main" value="False Positive">False Positive</option>
                      </select>
                    </td>
                    <td className="px-4 py-4 text-right text-text-muted group-hover:text-primary transition-colors">
                      <ChevronRight className="w-5 h-5 inline-block" />
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

export default AlertsList;
