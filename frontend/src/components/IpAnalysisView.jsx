import { useState, useEffect } from 'react';
import { getIpAnalysis, getSingleIpProfile } from '../services/api';
import { 
  Network, 
  Search, 
  Globe, 
  Lock, 
  X, 
  ArrowUpRight,
  Filter
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const ReputationBadge = ({ label }) => {
  const normalized = (label || 'Clean').toUpperCase();
  if (normalized.includes('POTENTIALLY MALICIOUS') || normalized.includes('CRITICAL')) {
    return <span className="px-2.5 py-1 rounded-md text-xs font-bold bg-red-500/15 text-red-400 border border-red-500/30">Potentially Malicious</span>;
  }
  if (normalized.includes('HIGH RISK')) {
    return <span className="px-2.5 py-1 rounded-md text-xs font-bold bg-orange-500/15 text-orange-400 border border-orange-500/30">High Risk</span>;
  }
  if (normalized.includes('SUSPICIOUS')) {
    return <span className="px-2.5 py-1 rounded-md text-xs font-bold bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">Suspicious</span>;
  }
  return <span className="px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">Clean / Normal</span>;
};

const IpAnalysisView = () => {
  const [ips, setIps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [selectedIpProfile, setSelectedIpProfile] = useState(null);
  const navigate = useNavigate();

  const fetchIps = async () => {
    try {
      setLoading(true);
      const data = await getIpAnalysis();
      setIps(data);
    } catch (err) {
      console.error('Failed to load IP analysis', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIps();
  }, []);

  const handleInspectIp = async (ipStr) => {
    try {
      const profile = await getSingleIpProfile(ipStr);
      setSelectedIpProfile(profile);
    } catch (err) {
      console.error('Failed to load IP profile', err);
    }
  };

  const filteredIps = ips.filter(item => {
    const matchesSearch = item.ip.toLowerCase().includes(search.toLowerCase());
    const matchesType = 
      typeFilter === 'ALL' || 
      (typeFilter === 'PUBLIC' && !item.is_private) ||
      (typeFilter === 'PRIVATE' && item.is_private) ||
      (typeFilter === 'SUSPICIOUS' && item.threat_count > 0);
    return matchesSearch && matchesType;
  });

  return (
    <div className="space-y-6 pb-12 relative">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-primary/10 border border-primary/20 rounded-xl text-primary">
              <Network className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-text-main">Threat Intelligence & IP Analysis</h2>
              <p className="text-text-muted text-sm mt-0.5">
                RFC 1918 classification, login failure tracking, threat activity, and risk scoring.
              </p>
            </div>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
            <input
              type="text"
              placeholder="Search IP address..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 bg-surface border border-surface-light rounded-xl text-sm focus:outline-none focus:border-primary/50 text-text-main w-56"
            />
          </div>

          <div className="relative">
            <Filter className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="pl-9 pr-8 py-2 bg-surface border border-surface-light rounded-xl text-sm focus:outline-none focus:border-primary/50 text-text-main appearance-none cursor-pointer"
            >
              <option value="ALL">All Network Types</option>
              <option value="PUBLIC">Public IPs</option>
              <option value="PRIVATE">RFC 1918 Private</option>
              <option value="SUSPICIOUS">Threats Detected</option>
            </select>
          </div>
        </div>
      </div>

      {/* Summary Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-surface border border-surface-light rounded-2xl p-4">
          <div className="text-xs text-text-muted font-medium uppercase tracking-wider">Total Unique IPs</div>
          <div className="text-2xl font-black text-text-main mt-1">{ips.length}</div>
        </div>
        <div className="bg-surface border border-surface-light rounded-2xl p-4">
          <div className="text-xs text-text-muted font-medium uppercase tracking-wider">Public IPs</div>
          <div className="text-2xl font-black text-cyan-400 mt-1">
            {ips.filter(i => !i.is_private).length}
          </div>
        </div>
        <div className="bg-surface border border-surface-light rounded-2xl p-4">
          <div className="text-xs text-text-muted font-medium uppercase tracking-wider">RFC 1918 Private</div>
          <div className="text-2xl font-black text-emerald-400 mt-1">
            {ips.filter(i => i.is_private).length}
          </div>
        </div>
        <div className="bg-surface border border-surface-light rounded-2xl p-4">
          <div className="text-xs text-text-muted font-medium uppercase tracking-wider">Suspicious / High Risk</div>
          <div className="text-2xl font-black text-danger mt-1">
            {ips.filter(i => i.threat_count > 0 || i.risk_score > 30).length}
          </div>
        </div>
      </div>

      {/* Main IP Table */}
      <div className="bg-surface rounded-2xl border border-surface-light overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-light/40 border-b border-surface-light text-text-muted text-xs uppercase tracking-wider">
                <th className="px-4 py-4 font-medium text-center w-14">S.No.</th>
                <th className="px-6 py-4 font-medium">IP Address</th>
                <th className="px-6 py-4 font-medium">Network Type</th>
                <th className="px-6 py-4 font-medium">Reputation Label</th>
                <th className="px-6 py-4 font-medium">Total Events</th>
                <th className="px-6 py-4 font-medium">Failed / Success Logins</th>
                <th className="px-6 py-4 font-medium">Risk Score</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-light">
              {loading ? (
                <tr>
                  <td colSpan="8" className="px-6 py-12 text-center text-text-muted animate-pulse">
                    Evaluating IP threat intelligence and login behaviors...
                  </td>
                </tr>
              ) : filteredIps.length === 0 ? (
                <tr>
                  <td colSpan="8" className="px-6 py-12 text-center text-text-muted">
                    <Network className="w-10 h-10 mx-auto mb-2 text-surface-light" />
                    <p className="text-base font-medium">No IP records found</p>
                    <p className="text-xs text-text-muted mt-1">Try clearing your filters or ingest log data.</p>
                  </td>
                </tr>
              ) : (
                filteredIps.map((item, idx) => (
                  <tr 
                    key={item.ip}
                    className="hover:bg-surface-light/30 transition-colors"
                  >
                    <td className="px-4 py-4 text-center text-text-muted font-mono text-xs font-medium">
                      {idx + 1}
                    </td>
                    <td className="px-6 py-4 font-mono font-medium text-primary-dark">
                      {item.ip}
                    </td>

                    <td className="px-6 py-4">
                      {item.is_private ? (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-surface-light text-text-muted border border-surface-light">
                          <Lock className="w-3 h-3 text-emerald-400" /> Private (RFC 1918)
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          <Globe className="w-3 h-3" /> Public Internet
                        </span>
                      )}
                    </td>

                    <td className="px-6 py-4">
                      <ReputationBadge label={item.reputation_label} />
                    </td>

                    <td className="px-6 py-4 text-sm font-semibold text-text-main">
                      {(item.total_events ?? item.request_count ?? 0).toLocaleString()}
                    </td>

                    <td className="px-6 py-4 text-xs font-mono">
                      <span className="text-danger font-bold">{item.failed_logins || 0} fails</span>
                      <span className="text-text-muted mx-1.5">/</span>
                      <span className="text-emerald-400 font-bold">{item.successful_logins || 0} success</span>
                    </td>

                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-background rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              item.risk_score >= 70 ? 'bg-danger' :
                              item.risk_score >= 40 ? 'bg-warning' :
                              'bg-primary'
                            }`}
                            style={{ width: `${Math.min(item.risk_score || 0, 100)}%` }}
                          />
                        </div>
                        <span className="text-xs font-bold">{Math.round(item.risk_score || 0)}</span>
                      </div>
                    </td>

                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => handleInspectIp(item.ip)}
                        className="px-3 py-1.5 rounded-lg bg-surface-light hover:bg-primary/10 hover:text-primary text-xs font-semibold transition-colors inline-flex items-center gap-1"
                      >
                        Profile <ArrowUpRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* IP Profile Forensic Drawer / Modal */}
      {selectedIpProfile && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end">
          <div className="w-full max-w-2xl bg-surface h-full border-l border-surface-light shadow-2xl p-6 overflow-y-auto flex flex-col justify-between">
            <div className="space-y-6">
              {/* Modal Header */}
              <div className="flex items-center justify-between border-b border-surface-light pb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-primary/10 rounded-xl text-primary">
                    <Network className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold font-mono text-text-main">{selectedIpProfile.ip}</h3>
                    <div className="flex items-center gap-2 mt-0.5">
                      <ReputationBadge label={selectedIpProfile.reputation_label} />
                      <span className="text-xs text-text-muted">
                        {selectedIpProfile.is_private ? 'RFC 1918 Private IP' : 'Public IP Address'}
                      </span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => setSelectedIpProfile(null)}
                  className="p-1.5 rounded-lg text-text-muted hover:text-text-main hover:bg-surface-light"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Metric Cards */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-background p-3.5 rounded-xl border border-surface-light">
                  <div className="text-[11px] text-text-muted uppercase">Risk Score</div>
                  <div className="text-xl font-black text-danger mt-0.5">
                    {Math.round(selectedIpProfile.risk_score || 0)}<span className="text-xs font-normal text-text-muted">/100</span>
                  </div>
                </div>
                <div className="bg-background p-3.5 rounded-xl border border-surface-light">
                  <div className="text-[11px] text-text-muted uppercase">Total Requests</div>
                  <div className="text-xl font-black text-text-main mt-0.5">
                    {selectedIpProfile.total_events ?? selectedIpProfile.request_count ?? 0}
                  </div>
                </div>
                <div className="bg-background p-3.5 rounded-xl border border-surface-light">
                  <div className="text-[11px] text-text-muted uppercase">Threat Count</div>
                  <div className="text-xl font-black text-warning mt-0.5">
                    {selectedIpProfile.threat_count || 0}
                  </div>
                </div>
              </div>

              {/* Auth Behaviors */}
              <div className="bg-background p-4 rounded-xl border border-surface-light space-y-2">
                <div className="text-xs font-bold uppercase text-text-muted tracking-wider">
                  Authentication Behaviors
                </div>
                <div className="flex justify-between text-sm py-1 border-b border-surface-light/40">
                  <span className="text-text-muted">Failed Authentication Attempts:</span>
                  <span className="font-mono font-bold text-danger">{selectedIpProfile.failed_logins || 0}</span>
                </div>
                <div className="flex justify-between text-sm py-1 border-b border-surface-light/40">
                  <span className="text-text-muted">Successful Authentications:</span>
                  <span className="font-mono font-bold text-emerald-400">{selectedIpProfile.successful_logins || 0}</span>
                </div>
                <div className="flex justify-between text-sm py-1">
                  <span className="text-text-muted">Target Usernames:</span>
                  <span className="font-mono text-text-main">
                    {(selectedIpProfile.target_users && selectedIpProfile.target_users.length > 0)
                      ? selectedIpProfile.target_users.join(', ')
                      : (selectedIpProfile.related_usernames && selectedIpProfile.related_usernames.length > 0)
                      ? selectedIpProfile.related_usernames.join(', ')
                      : 'None / N/A'}
                  </span>
                </div>
              </div>

              {/* Associated Alerts */}
              {(() => {
                const alertsList = selectedIpProfile.associated_alerts || selectedIpProfile.alerts || [];
                return alertsList.length > 0 ? (
                  <div className="space-y-2">
                    <div className="text-xs font-bold uppercase text-text-muted tracking-wider">
                      Associated Alerts ({alertsList.length})
                    </div>
                    <div className="space-y-2">
                      {alertsList.map((al, idx) => (
                        <div 
                          key={idx}
                          onClick={() => {
                            setSelectedIpProfile(null);
                            navigate(`/alerts/${al.id}`);
                          }}
                          className="p-3 bg-background hover:bg-surface-light/40 cursor-pointer rounded-xl border border-surface-light flex items-center justify-between"
                        >
                          <div>
                            <div className="font-semibold text-sm text-text-main">{al.threat_type}</div>
                            <div className="text-xs text-text-muted">{al.event}</div>
                          </div>
                          <span className="text-xs font-bold text-danger">{al.severity}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null;
              })()}

              {/* Recent Raw Logs */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase text-text-muted tracking-wider">
                    Recent Associated Logs
                  </span>
                  <button
                    onClick={() => {
                      setSelectedIpProfile(null);
                      navigate(`/logs?search=${encodeURIComponent(selectedIpProfile.ip)}`);
                    }}
                    className="text-xs text-primary hover:underline"
                  >
                    View All in Explorer
                  </button>
                </div>

                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {(selectedIpProfile.associated_logs || selectedIpProfile.recent_logs || []).slice(0, 10).map((lg, idx) => (
                    <div key={idx} className="p-2.5 bg-background rounded-lg border border-surface-light font-mono text-xs text-text-muted">
                      <div className="flex justify-between text-[11px] text-text-main mb-1">
                        <span className="text-cyan-400">{lg.event_type}</span>
                        <span>{new Date(lg.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <div className="truncate text-text-muted">{lg.message}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Footer Action */}
            <div className="pt-6 border-t border-surface-light">
              <button
                onClick={() => {
                  setSelectedIpProfile(null);
                  navigate(`/logs?search=${encodeURIComponent(selectedIpProfile.ip)}`);
                }}
                className="w-full py-2.5 rounded-xl bg-primary text-black font-bold text-sm hover:bg-primary-hover transition-colors text-center"
              >
                Perform Full Forensic Investigation in Explorer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default IpAnalysisView;
