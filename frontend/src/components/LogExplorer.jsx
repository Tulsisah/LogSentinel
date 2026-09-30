import { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { searchLogs, getLogDetails } from '../services/api';
import { 
  Search, 
  ChevronLeft, 
  ChevronRight, 
  FileText, 
  X, 
  ExternalLink, 
  RefreshCw, 
  Terminal, 
  AlertTriangle
} from 'lucide-react';

const SEVERITY_BADGES = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  INFO: 'bg-surface-light text-text-muted border-surface-light'
};

const LogExplorer = () => {
  const [searchParams] = useSearchParams();
  const initialSearch = searchParams.get('search') || searchParams.get('q') || '';

  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [loading, setLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState(initialSearch);
  const [severity, setSeverity] = useState('ALL');
  const [sourceIp, setSourceIp] = useState('');
  const [username, setUsername] = useState('');
  const [eventType, setEventType] = useState('ALL');
  const [authStatus, setAuthStatus] = useState('ALL');
  const [sortBy, setSortBy] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('desc');

  // Drawer detail state
  const [selectedLogId, setSelectedLogId] = useState(null);
  const [logDetail, setLogDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const params = {
        page,
        page_size: pageSize,
        q: search || undefined,
        severity: severity !== 'ALL' ? severity : undefined,
        source_ip: sourceIp || undefined,
        username: username || undefined,
        event_type: eventType !== 'ALL' ? eventType : undefined,
        auth_status: authStatus !== 'ALL' ? authStatus : undefined,
        sort_by: sortBy,
        sort_order: sortOrder
      };
      const res = await searchLogs(params);
      setLogs(res.items || []);
      setTotal(res.total || 0);
      setTotalPages(res.total_pages || 1);
    } catch (err) {
      console.error('Failed to search logs', err);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search, severity, sourceIp, username, eventType, authStatus, sortBy, sortOrder]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  useEffect(() => {
    const q = searchParams.get('search') || searchParams.get('q');
    if (q !== null && q !== undefined) {
      setSearch(q);
      setPage(1);
    }
  }, [searchParams]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchLogs();
  };

  const handleResetFilters = () => {
    setSearch('');
    setSeverity('ALL');
    setSourceIp('');
    setUsername('');
    setEventType('ALL');
    setAuthStatus('ALL');
    setSortBy('timestamp');
    setSortOrder('desc');
    setPage(1);
  };

  const openLogDetails = async (id) => {
    setSelectedLogId(id);
    setDetailLoading(true);
    try {
      const data = await getLogDetails(id);
      setLogDetail(data);
    } catch (err) {
      console.error('Failed to fetch log details', err);
    } finally {
      setDetailLoading(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Log Explorer & SIEM Search</h2>
          <p className="text-text-muted text-sm mt-1">
            Server-side filtered search across raw machine logs and parsed security attributes.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-text-muted">
            Found <strong>{total}</strong> matching event(s)
          </span>
          <button
            onClick={fetchLogs}
            className="p-2 bg-surface hover:bg-surface-light border border-surface-light rounded-xl text-text-muted hover:text-text-main transition-colors cursor-pointer"
            title="Refresh logs"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-surface rounded-2xl p-4 border border-surface-light shadow-sm space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col lg:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-text-muted" />
            <input
              type="text"
              placeholder="Search message, raw log, IP, URL path, user..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-background border border-surface-light rounded-xl text-sm focus:outline-none focus:border-primary/50 text-text-main transition-colors"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto">
            {/* Severity Filter */}
            <select
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
              className="px-3 py-2 bg-background border border-surface-light rounded-xl text-xs font-semibold focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>

            {/* Event Type Filter */}
            <select
              value={eventType}
              onChange={(e) => { setEventType(e.target.value); setPage(1); }}
              className="px-3 py-2 bg-background border border-surface-light rounded-xl text-xs font-semibold focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Event Types</option>
              <option value="failed_login">Failed Login</option>
              <option value="successful_login">Successful Login</option>
              <option value="privilege_escalation">Privilege Escalation</option>
              <option value="account_lockout">Account Lockout</option>
              <option value="web_request">Web Request</option>
              <option value="firewall">Firewall Traffic</option>
              <option value="command_execution">Command Execution</option>
            </select>

            {/* Auth Status Filter */}
            <select
              value={authStatus}
              onChange={(e) => { setAuthStatus(e.target.value); setPage(1); }}
              className="px-3 py-2 bg-background border border-surface-light rounded-xl text-xs font-semibold focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Auth Status</option>
              <option value="SUCCESS">SUCCESS</option>
              <option value="FAILED">FAILED</option>
            </select>

            <button
              type="submit"
              className="px-4 py-2 bg-primary hover:bg-primary-dark text-background rounded-xl text-xs font-bold transition-all cursor-pointer shadow-sm"
            >
              Apply Search
            </button>

            <button
              type="button"
              onClick={handleResetFilters}
              className="px-3 py-2 bg-surface-light/40 hover:bg-surface-light text-text-muted hover:text-text-main rounded-xl text-xs font-medium transition-colors cursor-pointer"
            >
              Reset
            </button>
          </div>
        </form>
      </div>

      {/* Logs Table */}
      <div className="bg-surface rounded-2xl border border-surface-light overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-light/40 border-b border-surface-light text-text-muted text-[11px] uppercase tracking-wider">
                <th className="px-4 py-3.5 font-semibold text-center w-16">S.No.</th>
                <th className="px-5 py-3.5 font-semibold">Timestamp</th>
                <th className="px-5 py-3.5 font-semibold">Severity</th>
                <th className="px-5 py-3.5 font-semibold">Source IP</th>
                <th className="px-5 py-3.5 font-semibold">Username</th>
                <th className="px-5 py-3.5 font-semibold">Event Type</th>
                <th className="px-5 py-3.5 font-semibold">Message Preview</th>
                <th className="px-5 py-3.5 font-semibold text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-light/60 text-xs">
              {loading ? (
                <tr>
                  <td colSpan="8" className="px-5 py-12 text-center text-text-muted animate-pulse">
                    Querying SIEM database...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan="8" className="px-5 py-16 text-center text-text-muted">
                    <FileText className="w-10 h-10 mx-auto mb-2 text-surface-light" />
                    <p className="text-sm font-semibold">No log entries matched query</p>
                    <p className="text-xs text-text-muted mt-1">Try broadening your search term or clearing filters.</p>
                  </td>
                </tr>
              ) : (
                logs.map((log, index) => (
                  <tr
                    key={log.id}
                    onClick={() => openLogDetails(log.id)}
                    className="hover:bg-surface-light/30 transition-colors cursor-pointer group"
                  >
                    <td className="px-4 py-3 text-center text-text-muted font-mono font-medium whitespace-nowrap">
                      {(page - 1) * pageSize + index + 1}
                    </td>
                    <td className="px-5 py-3 text-text-muted font-mono whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-5 py-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_BADGES[log.severity] || SEVERITY_BADGES.INFO}`}>
                        {log.severity}
                      </span>
                    </td>
                    <td className="px-5 py-3 font-mono text-primary-dark whitespace-nowrap">
                      {log.source_ip}
                    </td>
                    <td className="px-5 py-3 font-medium text-text-main whitespace-nowrap">
                      {log.username || '-'}
                    </td>
                    <td className="px-5 py-3 whitespace-nowrap">
                      <span className="font-mono text-[11px] bg-background px-2 py-0.5 rounded text-text-muted border border-surface-light/50">
                        {log.event_type}
                      </span>
                    </td>
                    <td className="px-5 py-3 max-w-xs truncate text-text-muted font-mono text-[11px]">
                      {log.message || log.raw_log}
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button className="text-xs text-primary group-hover:underline font-semibold flex items-center gap-1 justify-end ml-auto">
                        Inspect <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="px-5 py-3.5 bg-surface-light/20 border-t border-surface-light flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-text-muted">
          <div>
            Showing <strong>{(page - 1) * pageSize + 1}</strong> to <strong>{Math.min(page * pageSize, total)}</strong> of <strong>{total}</strong> entries
          </div>

          <div className="flex items-center gap-2">
            <select
              value={pageSize}
              onChange={(e) => { setPageSize(Number(e.target.value)); setPage(1); }}
              className="px-2 py-1 bg-background border border-surface-light rounded-lg text-xs"
            >
              <option value="25">25 / page</option>
              <option value="50">50 / page</option>
              <option value="100">100 / page</option>
            </select>

            <button
              onClick={() => setPage(p => Math.max(p - 1, 1))}
              disabled={page <= 1}
              className="p-1.5 bg-surface hover:bg-surface-light border border-surface-light rounded-lg disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>

            <span className="px-2 font-medium">Page {page} of {totalPages}</span>

            <button
              onClick={() => setPage(p => Math.min(p + 1, totalPages))}
              disabled={page >= totalPages}
              className="p-1.5 bg-surface hover:bg-surface-light border border-surface-light rounded-lg disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Expandable Log Detail Drawer / Modal */}
      {selectedLogId && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-sm flex justify-end animate-in fade-in">
          <div className="w-full max-w-2xl bg-surface border-l border-surface-light h-full overflow-y-auto p-6 shadow-2xl space-y-6">
            <div className="flex items-center justify-between border-b border-surface-light pb-4">
              <div>
                <h3 className="text-lg font-bold text-text-main flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-primary" />
                  Log Forensic Inspection
                </h3>
                <span className="text-xs font-mono text-text-muted">Event ID #{selectedLogId}</span>
              </div>
              <button
                onClick={() => { setSelectedLogId(null); setLogDetail(null); }}
                className="p-2 hover:bg-surface-light rounded-xl text-text-muted hover:text-text-main cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {detailLoading || !logDetail ? (
              <div className="p-12 text-center text-text-muted animate-pulse">Loading event forensic details...</div>
            ) : (
              <div className="space-y-6">
                {/* Overview Card */}
                <div className="bg-background rounded-xl p-5 border border-surface-light space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <span className="text-text-muted block mb-0.5">Timestamp (UTC):</span>
                      <span className="font-mono text-text-main">{new Date(logDetail.log.timestamp).toISOString()}</span>
                    </div>
                    <div>
                      <span className="text-text-muted block mb-0.5">Severity:</span>
                      <span className={`px-2 py-0.5 rounded font-bold border ${SEVERITY_BADGES[logDetail.log.severity] || SEVERITY_BADGES.INFO}`}>
                        {logDetail.log.severity}
                      </span>
                    </div>
                    <div>
                      <span className="text-text-muted block mb-0.5">Source IP:</span>
                      <span className="font-mono text-primary font-bold">{logDetail.log.source_ip}</span>
                    </div>
                    <div>
                      <span className="text-text-muted block mb-0.5">Destination IP:</span>
                      <span className="font-mono">{logDetail.log.destination_ip || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-text-muted block mb-0.5">Username:</span>
                      <span className="font-bold text-text-main">{logDetail.log.username || 'Unknown'}</span>
                    </div>
                    <div>
                      <span className="text-text-muted block mb-0.5">Event Type:</span>
                      <span className="font-mono bg-surface px-2 py-0.5 rounded border border-surface-light">{logDetail.log.event_type}</span>
                    </div>
                    {logDetail.log.http_method && (
                      <div>
                        <span className="text-text-muted block mb-0.5">HTTP Method:</span>
                        <span className="font-mono">{logDetail.log.http_method}</span>
                      </div>
                    )}
                    {logDetail.log.status_code && (
                      <div>
                        <span className="text-text-muted block mb-0.5">Status Code:</span>
                        <span className="font-mono">{logDetail.log.status_code}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Threat Detection & Anomaly Reason */}
                <div className="bg-surface-light/20 rounded-xl p-5 border border-surface-light space-y-2">
                  <h4 className="text-xs font-bold text-warning uppercase flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-warning" /> Why it is Suspicious / Threat Analysis
                  </h4>
                  <p className="text-xs text-text-main leading-relaxed">
                    {logDetail.why_suspicious}
                  </p>
                  {logDetail.alert && (
                    <div className="pt-2 text-[11px] text-text-muted flex items-center gap-2">
                      <span>Trigger Rule: <strong className="font-mono text-primary">{logDetail.alert.detection_rule}</strong></span>
                      &bull;
                      <span>Risk Score: <strong className="text-danger font-bold">{logDetail.alert.risk_score}/100</strong></span>
                    </div>
                  )}
                </div>

                {/* Original Raw Log */}
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-text-muted uppercase">Original Raw Telemetry</h4>
                  <div className="bg-background rounded-xl p-4 border border-surface-light font-mono text-[11px] text-text-main whitespace-pre-wrap break-all leading-relaxed">
                    {logDetail.log.raw_log}
                  </div>
                </div>

                {/* Recommended Defensive Action */}
                <div className="bg-primary/10 rounded-xl p-4 border border-primary/20 space-y-1">
                  <h4 className="text-xs font-bold text-primary uppercase">Recommended Defensive Action</h4>
                  <p className="text-xs text-text-main">{logDetail.recommended_action}</p>
                </div>

                {/* Related Events from Same Source */}
                {logDetail.related_events && logDetail.related_events.length > 0 && (
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold text-text-muted uppercase">Related Events from {logDetail.log.source_ip}</h4>
                    <div className="bg-background rounded-xl divide-y divide-surface-light border border-surface-light text-xs">
                      {logDetail.related_events.map(ev => (
                        <div key={ev.id} className="p-3 flex items-center justify-between">
                          <div>
                            <span className="font-mono text-[11px] text-text-muted block">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                            <span className="font-medium text-text-main">{ev.event_type}</span>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_BADGES[ev.severity] || SEVERITY_BADGES.INFO}`}>
                            {ev.severity}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default LogExplorer;
