import { useState, useEffect, useCallback } from 'react';
import { getIncidents, updateIncidentStatus } from '../services/api';
import { 
  Flame, 
  Clock, 
  ArrowRight, 
  ChevronDown, 
  ChevronUp, 
  Layers, 
  Network, 
  User, 
  ExternalLink 
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const SeverityBadge = ({ severity }) => {
  const colors = {
    CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
    HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    MEDIUM: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  };
  return (
    <span className={`px-2.5 py-1 rounded-md text-xs font-bold border ${colors[severity] || colors.LOW}`}>
      {severity}
    </span>
  );
};

const IncidentsView = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState(null);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const navigate = useNavigate();

  const fetchIncidents = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getIncidents();
      setIncidents(data);
      if (data.length > 0 && !expandedId) {
        setExpandedId(data[0].id);
      }
    } catch (err) {
      console.error('Failed to load incidents', err);
    } finally {
      setLoading(false);
    }
  }, [expandedId]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  const handleStatusChange = async (incidentId, newStatus) => {
    try {
      await updateIncidentStatus(incidentId, newStatus);
      setIncidents(incidents.map(inc => inc.id === incidentId ? { ...inc, status: newStatus } : inc));
    } catch (err) {
      console.error('Failed to update incident status', err);
    }
  };

  const filteredIncidents = incidents.filter(inc => {
    if (statusFilter === 'ALL') return true;
    return inc.status.toUpperCase() === statusFilter.toUpperCase();
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-danger/10 border border-danger/20 rounded-xl text-danger">
              <Flame className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-text-main">Multi-Stage Incidents</h2>
              <p className="text-text-muted text-sm mt-0.5">
                Correlated attack progressions linked by temporal proximity and entity footprint.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs text-text-muted">Filter Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-surface border border-surface-light text-text-main rounded-xl px-3 py-2 text-sm focus:outline-none focus:border-primary/50"
          >
            <option value="ALL">All Incidents ({incidents.length})</option>
            <option value="New">New / Open</option>
            <option value="Investigating">Investigating</option>
            <option value="Resolved">Resolved</option>
            <option value="False Positive">False Positive</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="p-12 text-center text-text-muted bg-surface rounded-2xl border border-surface-light animate-pulse">
          Correlating incidents and timeline progression...
        </div>
      ) : filteredIncidents.length === 0 ? (
        <div className="bg-surface rounded-2xl border border-surface-light p-12 text-center text-text-muted">
          <Layers className="w-12 h-12 mx-auto mb-3 text-surface-light" />
          <p className="text-lg font-medium text-text-main">No correlated incidents found</p>
          <p className="text-sm mt-1">Upload logs with multi-stage attack patterns or sample APT data to generate incident timelines.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredIncidents.map((incident) => {
            const isExpanded = expandedId === incident.id;
            const timeline = Array.isArray(incident.attack_timeline) ? incident.attack_timeline : [];
            const tactics = Array.isArray(incident.mitre_tactics) ? incident.mitre_tactics : [];
            const affectedUsers = Array.isArray(incident.affected_users) ? incident.affected_users : [];

            return (
              <div 
                key={incident.id} 
                className="bg-surface border border-surface-light rounded-2xl overflow-hidden shadow-sm transition-all"
              >
                {/* Incident Header Card */}
                <div 
                  onClick={() => setExpandedId(isExpanded ? null : incident.id)}
                  className="p-5 cursor-pointer hover:bg-surface-light/20 flex flex-col lg:flex-row lg:items-center justify-between gap-4 select-none"
                >
                  <div className="flex items-start gap-4">
                    <div className="mt-1">
                      <SeverityBadge severity={incident.severity} />
                    </div>
                    <div>
                      <div className="flex items-center gap-3">
                        <h3 className="text-lg font-bold text-text-main hover:text-primary transition-colors">
                          {incident.title}
                        </h3>
                        <span className="text-xs font-mono text-text-muted">#{incident.id}</span>
                      </div>
                      <p className="text-sm text-text-muted mt-1 line-clamp-2 max-w-3xl">
                        {incident.summary}
                      </p>
                      
                      <div className="flex flex-wrap items-center gap-3 mt-3 text-xs text-text-muted">
                        <div className="flex items-center gap-1.5 font-mono text-primary-dark">
                          <Network className="w-3.5 h-3.5 text-primary" />
                          <span>{incident.primary_ip || 'Multiple IPs'}</span>
                        </div>
                        {affectedUsers.length > 0 && (
                          <div className="flex items-center gap-1.5 text-text-main">
                            <User className="w-3.5 h-3.5 text-warning" />
                            <span>{affectedUsers.join(', ')}</span>
                          </div>
                        )}
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5" />
                          <span>{timeline.length} Progression Steps</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Right side metrics and status */}
                  <div className="flex items-center gap-4 shrink-0 justify-between lg:justify-end border-t lg:border-t-0 pt-3 lg:pt-0 border-surface-light">
                    <div className="text-right">
                      <div className="text-[10px] uppercase font-bold text-text-muted tracking-wider">Risk Score</div>
                      <div className="text-xl font-black text-danger">
                        {Math.round(incident.risk_score)}<span className="text-xs font-normal text-text-muted">/100</span>
                      </div>
                    </div>

                    <div onClick={(e) => e.stopPropagation()}>
                      <select
                        value={incident.status}
                        onChange={(e) => handleStatusChange(incident.id, e.target.value)}
                        className={`text-xs font-bold px-3 py-1.5 rounded-lg border focus:outline-none cursor-pointer ${
                          incident.status === 'New' || incident.status === 'OPEN' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                          incident.status === 'Investigating' ? 'bg-purple-500/10 text-purple-400 border-purple-500/30' :
                          incident.status === 'False Positive' ? 'bg-surface-light text-text-muted border-surface-light' :
                          'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        }`}
                      >
                        <option className="bg-surface text-text-main" value="New">New</option>
                        <option className="bg-surface text-text-main" value="Investigating">Investigating</option>
                        <option className="bg-surface text-text-main" value="Resolved">Resolved</option>
                        <option className="bg-surface text-text-main" value="False Positive">False Positive</option>
                      </select>
                    </div>

                    <button 
                      className="p-1.5 rounded-lg bg-surface-light/40 hover:bg-surface-light text-text-muted hover:text-text-main"
                      aria-label="Toggle details"
                    >
                      {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                    </button>
                  </div>
                </div>

                {/* Expanded Attack Timeline & Entities */}
                {isExpanded && (
                  <div className="border-t border-surface-light bg-background/50 p-6 space-y-6">
                    {/* MITRE Tactics Tags */}
                    {tactics.length > 0 && (
                      <div>
                        <div className="text-xs font-bold uppercase text-text-muted tracking-wider mb-2">
                          MITRE ATT&CK Framework Mapping
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {tactics.map((tactic, idx) => (
                            <span 
                              key={idx} 
                              className="px-2.5 py-1 bg-surface-light/80 border border-surface-light rounded-lg text-xs font-mono text-cyan-300"
                            >
                              {tactic}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Step-by-Step Chronological Progression */}
                    <div>
                      <div className="text-xs font-bold uppercase text-text-muted tracking-wider mb-4 flex items-center gap-2">
                        <Clock className="w-4 h-4 text-primary" />
                        Attack Timeline & Progression Flow
                      </div>

                      <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-surface-light">
                        {timeline.length === 0 ? (
                          <div className="text-sm text-text-muted">No timeline progression steps recorded.</div>
                        ) : (
                          timeline.map((step, idx) => {
                            const isCrit = step.severity === 'CRITICAL';
                            const isHigh = step.severity === 'HIGH';

                            return (
                              <div key={idx} className="relative group">
                                {/* Node dot */}
                                <div className={`absolute -left-[27px] top-1 w-4 h-4 rounded-full border-2 border-background flex items-center justify-center text-[9px] font-bold ${
                                  isCrit ? 'bg-danger text-white' :
                                  isHigh ? 'bg-warning text-white' :
                                  'bg-primary text-black'
                                }`}>
                                  {step.step || idx + 1}
                                </div>

                                <div className="bg-surface border border-surface-light rounded-xl p-4 hover:border-primary/40 transition-colors">
                                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                                    <div className="flex items-center gap-2">
                                      <span className="font-bold text-text-main text-sm">
                                        Step {step.step || idx + 1}: {step.stage || step.threat_type}
                                      </span>
                                      <SeverityBadge severity={step.severity} />
                                    </div>
                                    <span className="text-xs font-mono text-text-muted">
                                      {step.timestamp ? new Date(step.timestamp).toLocaleTimeString() : 'N/A'}
                                    </span>
                                  </div>

                                  <p className="text-sm text-text-muted mb-3">
                                    {step.description || step.event}
                                  </p>

                                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-surface-light/40 text-xs">
                                    <div className="flex items-center gap-3 text-text-muted">
                                      {step.source_ip && (
                                        <span className="font-mono text-primary-dark">IP: {step.source_ip}</span>
                                      )}
                                      {step.technique && (
                                        <span className="font-mono bg-background px-2 py-0.5 rounded text-cyan-400">
                                          {step.technique}
                                        </span>
                                      )}
                                    </div>

                                    {step.alert_id && (
                                      <button 
                                        onClick={() => navigate(`/alerts/${step.alert_id}`)}
                                        className="text-primary hover:underline flex items-center gap-1 font-medium"
                                      >
                                        Inspect Alert <ExternalLink className="w-3 h-3" />
                                      </button>
                                    )}
                                  </div>
                                </div>
                              </div>
                            );
                          })
                        )}
                      </div>
                    </div>

                    {/* Investigation Links */}
                    <div className="pt-2 flex items-center justify-between">
                      <button
                        onClick={() => navigate(`/logs?search=${encodeURIComponent(incident.primary_ip || '')}`)}
                        className="text-xs text-primary hover:underline flex items-center gap-1.5"
                      >
                        Explore all raw logs for IP {incident.primary_ip} <ArrowRight className="w-3.5 h-3.5" />
                      </button>

                      <div className="text-xs text-text-muted">
                        First Seen: <span className="text-text-main font-mono">{incident.first_seen ? new Date(incident.first_seen).toLocaleString() : 'N/A'}</span>
                        <span className="mx-2">•</span>
                        Last Seen: <span className="text-text-main font-mono">{incident.last_seen ? new Date(incident.last_seen).toLocaleString() : 'N/A'}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default IncidentsView;
