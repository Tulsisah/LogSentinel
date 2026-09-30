import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getAlertDetails, updateAlertStatus } from '../services/api';
import { ArrowLeft, ShieldAlert, Cpu, Activity, User, Network, FileTerminal, Target, HelpCircle, CheckCircle } from 'lucide-react';

const AlertDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchAlertDetails = useCallback(async () => {
    try {
      const data = await getAlertDetails(id);
      setAlert(data);
    } catch (error) {
      console.error('Failed to fetch alert details', error);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchAlertDetails();
  }, [fetchAlertDetails]);

  const handleStatusChange = async (newStatus) => {
    if (!alert) return;
    try {
      await updateAlertStatus(alert.id, newStatus);
      setAlert({ ...alert, status: newStatus });
    } catch (error) {
      console.error('Failed to update status', error);
    }
  };

  if (loading) {
    return <div className="p-8 text-center text-text-muted animate-pulse">Loading investigation details...</div>;
  }

  if (!alert) {
    return (
      <div className="p-8 text-center text-text-muted">
        <h2 className="text-xl mb-4">Alert Not Found</h2>
        <button onClick={() => navigate('/alerts')} className="text-primary hover:underline flex items-center justify-center gap-2 mx-auto">
          <ArrowLeft className="w-4 h-4" /> Back to Alerts
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <button 
          onClick={() => navigate('/alerts')}
          className="flex items-center gap-2 text-text-muted hover:text-text-main transition-colors px-3 py-1.5 rounded-lg hover:bg-surface-light"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Alerts</span>
        </button>
        
        <div className="flex items-center gap-3">
          <span className="text-sm text-text-muted">Incident Status:</span>
          <select 
            value={alert.status}
            onChange={(e) => handleStatusChange(e.target.value)}
            className={`px-4 py-1.5 rounded-lg text-sm font-medium border focus:outline-none appearance-none cursor-pointer
              ${alert.status === 'New' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' : 
                alert.status === 'Investigating' ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' : 
                alert.status === 'Resolved' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 
                'bg-surface text-text-muted border-surface-light'}`}
          >
            <option className="bg-surface text-text-main" value="New">New</option>
            <option className="bg-surface text-text-main" value="Investigating">Investigating</option>
            <option className="bg-surface text-text-main" value="Resolved">Resolved</option>
            <option className="bg-surface text-text-main" value="False Positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Main Info Card */}
      <div className="bg-surface rounded-2xl border border-surface-light shadow-xl overflow-hidden relative">
        <div className={`absolute top-0 left-0 w-1 h-full ${
          alert.severity === 'CRITICAL' ? 'bg-danger' : 
          alert.severity === 'HIGH' ? 'bg-warning' : 
          alert.severity === 'MEDIUM' ? 'bg-yellow-500' : 'bg-primary'
        }`} />
        
        <div className="p-8">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8 border-b border-surface-light pb-6">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <ShieldAlert className={`w-6 h-6 ${
                  alert.severity === 'CRITICAL' ? 'text-danger' : 
                  alert.severity === 'HIGH' ? 'text-warning' : 
                  alert.severity === 'MEDIUM' ? 'text-yellow-500' : 'text-primary'
                }`} />
                <h1 className="text-2xl font-black">{alert.threat_type}</h1>
              </div>
              <p className="text-text-muted text-lg">{alert.event}</p>
            </div>
            
            <div className="flex items-center gap-6 bg-background rounded-xl p-4 border border-surface-light">
              <div className="text-center">
                <div className="text-xs text-text-muted mb-1">Severity</div>
                <div className={`font-black text-lg ${
                  alert.severity === 'CRITICAL' ? 'text-danger' : 
                  alert.severity === 'HIGH' ? 'text-warning' : 
                  alert.severity === 'MEDIUM' ? 'text-yellow-500' : 'text-primary'
                }`}>{alert.severity}</div>
              </div>
              <div className="w-px h-10 bg-surface-light"></div>
              <div className="text-center">
                <div className="text-xs text-text-muted mb-1">Risk Score</div>
                <div className="font-black text-2xl tracking-tight">{Math.round(alert.risk_score)}<span className="text-sm font-normal text-text-muted">/100</span></div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="space-y-6">
              <h3 className="text-lg font-bold flex items-center gap-2"><Target className="w-5 h-5 text-primary" /> Entities Involved</h3>
              
              <div className="bg-background rounded-xl p-5 border border-surface-light space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 text-text-muted">
                    <Network className="w-4 h-4" /> Source IP
                  </div>
                  <div className="font-mono text-primary-dark font-medium">{alert.source_ip}</div>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 text-text-muted">
                    <User className="w-4 h-4" /> Username
                  </div>
                  <div className="font-medium text-text-main">{alert.username || 'Unknown'}</div>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 text-text-muted">
                    <Activity className="w-4 h-4" /> Timestamp
                  </div>
                  <div className="text-sm">{new Date(alert.timestamp).toLocaleString()}</div>
                </div>
                {alert.mitre_technique && (
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 text-text-muted">
                      <FileTerminal className="w-4 h-4" /> MITRE ATT&CK
                    </div>
                    <div className="bg-surface px-2 py-1 rounded text-xs font-mono">{alert.mitre_technique}</div>
                  </div>
                )}
              </div>
            </div>

            <div className="space-y-6">
              <h3 className="text-lg font-bold flex items-center gap-2"><HelpCircle className="w-5 h-5 text-warning" /> Detection Reason & Scoring</h3>
              
              <div className="bg-background rounded-xl p-5 border border-surface-light h-[180px] overflow-y-auto space-y-3">
                <p className="text-text-main leading-relaxed text-sm">{alert.detection_reason}</p>

                {alert.rule_name && (
                  <div className="text-xs text-text-muted">
                    <span className="font-semibold text-primary">Triggered Rule:</span> {alert.rule_name}
                  </div>
                )}

                {(() => {
                  const parsedFactors = Array.isArray(alert.risk_factors)
                    ? alert.risk_factors
                    : typeof alert.risk_factors === 'string'
                    ? alert.risk_factors.includes('derived from: ')
                      ? alert.risk_factors.split('derived from: ')[1]?.replace(/\.$/, '').split('; ') || [alert.risk_factors]
                      : [alert.risk_factors]
                    : [];

                  return parsedFactors.length > 0 ? (
                    <div className="pt-2 border-t border-surface-light">
                      <div className="text-[11px] font-bold text-text-muted uppercase tracking-wider mb-1">
                        Scoring Factors Breakdown:
                      </div>
                      <ul className="text-xs text-text-muted space-y-1">
                        {parsedFactors.map((factor, fIdx) => (
                          <li key={fIdx} className="flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-warning shrink-0"></span>
                            <span>{factor}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null;
                })()}
                
                {alert.ml_anomaly_result && (
                  <div className="pt-3 border-t border-surface-light flex items-start gap-3">
                    <Cpu className="w-5 h-5 text-purple-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="text-xs font-bold text-purple-400 mb-1 uppercase tracking-wider">AI Anomaly Detection</div>
                      <div className="text-sm text-text-muted">{alert.ml_anomaly_result}</div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
          
          {alert.original_log && (
            <div className="mt-8 space-y-4">
              <h3 className="text-lg font-bold flex items-center gap-2"><FileTerminal className="w-5 h-5 text-primary" /> Original Log Details</h3>
              <div className="bg-background rounded-xl p-5 border border-surface-light overflow-x-auto">
                <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
                  <div><span className="text-text-muted">Event Type:</span> <span className="font-mono">{alert.original_log.event_type}</span></div>
                  <div><span className="text-text-muted">Original Severity:</span> <span className="font-mono">{alert.original_log.severity}</span></div>
                  <div className="col-span-2"><span className="text-text-muted">Message:</span> <span className="font-mono">{alert.original_log.message}</span></div>
                </div>
                <div className="bg-surface-light/50 p-3 rounded font-mono text-xs text-text-muted whitespace-pre-wrap">
                  {alert.original_log.raw_log}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Recommended Action */}
      <div className="bg-surface-light/30 rounded-2xl p-6 border border-primary/20 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-32 h-32 bg-primary/10 rounded-full blur-3xl -mr-10 -mt-10"></div>
        <h3 className="text-lg font-bold flex items-center gap-2 mb-4 relative z-10"><CheckCircle className="w-5 h-5 text-primary" /> Recommended Action</h3>
        <p className="text-text-main relative z-10">{alert.recommended_action}</p>
      </div>
    </div>
  );
};

export default AlertDetails;
