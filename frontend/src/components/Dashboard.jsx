import { useState, useEffect, useCallback } from 'react';
import { getDashboardStats } from '../services/api';
import { 
  Activity, 
  ShieldAlert, 
  AlertTriangle, 
  Users, 
  Flame, 
  Lock, 
  Cpu, 
  Gauge, 
  KeyRound,
  ArrowRight,
  TrendingUp
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell,
  AreaChart,
  Area
} from 'recharts';
import { useNavigate } from 'react-router-dom';

const SEV_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f59e0b',
  MEDIUM: '#3b82f6',
  LOW: '#10b981',
  INFO: '#94a3b8'
};

const TOOLTIP_STYLE = {
  backgroundColor: 'var(--color-surface)',
  borderColor: 'var(--color-surface-light)',
  borderRadius: '0.75rem',
  color: 'var(--color-text-main)',
  boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
};

const StatCard = ({ title, value, subtitle, icon: Icon, colorClass, onClick, cursorClass }) => (
  <div 
    className={`bg-surface rounded-2xl p-5 border border-surface-light hover:border-primary/50 transition-all shadow-sm group ${cursorClass || ''}`}
    onClick={onClick}
  >
    <div className="flex items-center justify-between mb-3">
      <h3 className="text-text-muted text-xs font-semibold uppercase tracking-wider group-hover:text-text-main transition-colors">{title}</h3>
      <div className={`p-2.5 rounded-xl bg-opacity-10 ${colorClass.replace('text', 'bg')} group-hover:scale-110 transition-transform`}>
        <Icon className={`w-5 h-5 ${colorClass}`} />
      </div>
    </div>
    <div className="text-3xl font-black text-text-main">{value !== undefined ? value : '-'}</div>
    {subtitle && <div className="text-xs text-text-muted mt-1">{subtitle}</div>}
  </div>
);

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const fetchStats = useCallback(async () => {
    try {
      const data = await getDashboardStats();
      setStats(data);
    } catch (error) {
      console.error('Failed to fetch dashboard stats', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 20000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-text-muted gap-3">
        <Activity className="w-8 h-8 animate-spin text-primary" />
        <span className="text-sm font-medium">Aggregating SOC security metrics...</span>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-text-muted gap-3 bg-surface rounded-2xl border border-surface-light p-8">
        <AlertTriangle className="w-10 h-10 text-warning" />
        <span className="text-base font-semibold text-text-main">Unable to load telemetry metrics</span>
        <span className="text-xs text-text-muted">Ensure backend is active and reachable on port 8000.</span>
        <button 
          onClick={fetchStats}
          className="mt-2 px-5 py-2.5 bg-primary text-black font-bold text-xs rounded-xl hover:bg-primary-dark transition-colors shadow-sm cursor-pointer"
        >
          Retry Loading Metrics
        </button>
      </div>
    );
  }

  const riskScore = stats?.summary?.overall_risk_score || 0;
  const riskLevel = stats?.summary?.overall_risk_level || 'Low';

  const getRiskBadgeColor = (level) => {
    switch (level) {
      case 'Critical': return 'bg-red-500/20 text-red-500 border-red-500/30';
      case 'High': return 'bg-orange-500/20 text-orange-500 border-orange-500/30';
      case 'Medium': return 'bg-yellow-500/20 text-yellow-500 border-yellow-500/30';
      case 'Moderate': return 'bg-blue-500/20 text-blue-500 border-blue-500/30';
      default: return 'bg-emerald-500/20 text-emerald-500 border-emerald-500/30';
    }
  };

  return (
    <div className="space-y-6 pb-8">
      {/* Top Banner with Overall Risk Score */}
      <div className="bg-surface rounded-2xl p-6 border border-surface-light shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6 relative overflow-hidden">
        <div className="space-y-1 relative z-10">
          <div className="flex items-center gap-3">
            <h2 className="text-2xl font-black tracking-tight">Security Operations Overview</h2>
            <span className={`px-3 py-1 rounded-full text-xs font-bold border ${getRiskBadgeColor(riskLevel)}`}>
              Risk Level: {riskLevel}
            </span>
          </div>
          <p className="text-text-muted text-sm">
            Live telemetry monitoring, heuristic rule triggers, and automated ML anomaly classification.
          </p>
        </div>

        {/* Overall Risk Score Meter */}
        <div className="flex items-center gap-6 bg-background/80 rounded-2xl p-4 border border-surface-light shrink-0 relative z-10">
          <div className="relative flex items-center justify-center">
            <Gauge className={`w-12 h-12 ${riskScore >= 80 ? 'text-danger' : riskScore >= 60 ? 'text-warning' : riskScore >= 40 ? 'text-blue-400' : 'text-primary'}`} />
          </div>
          <div>
            <div className="text-xs text-text-muted uppercase font-semibold">Overall Risk Score</div>
            <div className="text-3xl font-black tracking-tight">
              {riskScore}<span className="text-sm font-normal text-text-muted">/100</span>
            </div>
            <div className="text-[11px] text-text-muted">
              {riskScore >= 81 ? 'Urgent SOC action required' : riskScore >= 61 ? 'High threat activity' : 'Telemetry within normal limits'}
            </div>
          </div>
        </div>
      </div>

      {/* 8 Primary SOC Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard 
          title="Total Logs" 
          value={stats?.summary?.total_logs} 
          subtitle="Processed events" 
          icon={Activity} 
          colorClass="text-blue-500" 
          cursorClass="cursor-pointer"
          onClick={() => navigate('/logs')}
        />
        <StatCard 
          title="Threats Detected" 
          value={stats?.summary?.threats_detected} 
          subtitle="Active alerts" 
          icon={ShieldAlert} 
          colorClass="text-warning" 
          cursorClass="cursor-pointer"
          onClick={() => navigate('/alerts')} 
        />
        <StatCard 
          title="Critical Alerts" 
          value={stats?.summary?.critical_alerts} 
          subtitle="P1 severity" 
          icon={AlertTriangle} 
          colorClass="text-danger" 
          cursorClass="cursor-pointer"
          onClick={() => navigate('/alerts', { state: { filterSeverity: 'CRITICAL' } })} 
        />
        <StatCard 
          title="High Severity" 
          value={stats?.summary?.high_risk_events} 
          subtitle="P2 severity" 
          icon={Flame} 
          colorClass="text-orange-500" 
          cursorClass="cursor-pointer"
          onClick={() => navigate('/alerts', { state: { filterSeverity: 'HIGH' } })} 
        />
        <StatCard 
          title="Failed Logins" 
          value={stats?.summary?.failed_logins} 
          subtitle="Auth failures" 
          icon={Lock} 
          colorClass="text-red-400" 
          cursorClass="cursor-pointer"
          onClick={() => navigate('/logs')}
        />
        <StatCard 
          title="Account Lockouts" 
          value={stats?.summary?.account_lockouts} 
          subtitle="Policy triggers" 
          icon={KeyRound} 
          colorClass="text-yellow-400" 
        />
        <StatCard 
          title="ML Anomalies" 
          value={stats?.summary?.anomalies} 
          subtitle="Isolation Forest" 
          icon={Cpu} 
          colorClass="text-purple-400" 
          cursorClass="cursor-pointer"
          onClick={() => navigate('/alerts')}
        />
        <StatCard 
          title="Unique IPs" 
          value={stats?.summary?.unique_ips} 
          subtitle="Seen endpoints" 
          icon={Users} 
          colorClass="text-primary" 
          cursorClass="cursor-pointer"
          onClick={() => navigate('/ips')}
        />
      </div>

      {/* Row 2: Events Timeline & Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Events Over Time Timeline (Span 2) */}
        <div className="lg:col-span-2 bg-surface rounded-2xl p-6 border border-surface-light shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-text-main flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-primary" />
                Security Events & Threats Timeline
              </h3>
              <p className="text-xs text-text-muted">Chronological traffic volume and correlated alert spikes</p>
            </div>
          </div>
          <div className="h-64">
            {stats?.charts?.events_over_time && stats.charts.events_over_time.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.charts.events_over_time}>
                  <defs>
                    <linearGradient id="eventsColor" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="threatsColor" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-surface-light)" />
                  <XAxis dataKey="time" stroke="var(--color-text-muted)" textAnchor="end" tick={{ fontSize: 11 }} />
                  <YAxis stroke="var(--color-text-muted)" tick={{ fontSize: 11 }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Area type="monotone" dataKey="events" stroke="#10b981" fillOpacity={1} fill="url(#eventsColor)" name="Total Events" />
                  <Area type="monotone" dataKey="threats" stroke="#ef4444" fillOpacity={1} fill="url(#threatsColor)" name="Security Threats" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-text-muted text-sm">No temporal events recorded</div>
            )}
          </div>
        </div>

        {/* Severity Distribution Pie (Span 1) */}
        <div className="bg-surface rounded-2xl p-6 border border-surface-light shadow-sm flex flex-col justify-between">
          <div>
            <h3 className="text-base font-bold text-text-main mb-1">Alerts by Severity</h3>
            <p className="text-xs text-text-muted">Proportional breakdown of security alerts</p>
          </div>
          <div className="h-56">
            {stats?.charts?.severity && stats.charts.severity.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats.charts.severity}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {stats.charts.severity.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SEV_COLORS[entry.name] || '#3b82f6'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-text-muted text-sm">No alert data available</div>
            )}
          </div>
          <div className="flex items-center justify-center gap-4 text-xs">
            {stats?.charts?.severity?.map((s) => (
              <div key={s.name} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: SEV_COLORS[s.name] || '#3b82f6' }} />
                <span className="text-text-muted">{s.name}: <strong>{s.value}</strong></span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 3: Threat Types & Top Suspicious IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Type Distribution */}
        <div className="bg-surface rounded-2xl p-6 border border-surface-light shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-text-main">Threat Type Distribution</h3>
              <p className="text-xs text-text-muted">Detected attack patterns and cyber techniques</p>
            </div>
          </div>
          <div className="h-64">
            {stats?.charts?.attack_types && stats.charts.attack_types.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.charts.attack_types} layout="vertical" margin={{ top: 5, right: 30, left: 30, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-surface-light)" horizontal={false} />
                  <XAxis type="number" stroke="var(--color-text-muted)" tick={{ fontSize: 11 }} />
                  <YAxis dataKey="type" type="category" stroke="var(--color-text-muted)" width={140} tick={{ fontSize: 11 }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="count" fill="#f59e0b" radius={[0, 6, 6, 0]} barSize={18} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-text-muted text-sm">No threat types registered</div>
            )}
          </div>
        </div>

        {/* Top Suspicious IPs */}
        <div className="bg-surface rounded-2xl p-6 border border-surface-light shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-text-main">Top Suspicious IP Addresses</h3>
              <p className="text-xs text-text-muted">Endpoints with highest alert frequency</p>
            </div>
            <button 
              onClick={() => navigate('/ips')} 
              className="text-xs text-primary hover:underline flex items-center gap-1 font-medium"
            >
              Full IP Analysis <ArrowRight className="w-3 h-3" />
            </button>
          </div>
          <div className="h-64">
            {stats?.charts?.top_ips && stats.charts.top_ips.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.charts.top_ips} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-surface-light)" horizontal={false} />
                  <XAxis type="number" stroke="var(--color-text-muted)" tick={{ fontSize: 11 }} />
                  <YAxis dataKey="ip" type="category" stroke="var(--color-text-muted)" width={110} tick={{ fontSize: 11, fontFamily: 'monospace' }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="count" fill="#ef4444" radius={[0, 6, 6, 0]} barSize={18} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-text-muted text-sm">No suspicious IPs recorded</div>
            )}
          </div>
        </div>
      </div>

      {/* Row 4: Authentication Analytics & Targeted Users */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Authentication Chart */}
        <div className="bg-surface rounded-2xl p-6 border border-surface-light shadow-sm">
          <h3 className="text-base font-bold text-text-main mb-1">Authentication Success vs. Failure</h3>
          <p className="text-xs text-text-muted mb-4">Logon attempts comparison across all endpoints</p>
          <div className="h-56">
            {stats?.charts?.auth_chart ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.charts.auth_chart} margin={{ top: 10, right: 30, left: 10, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-surface-light)" vertical={false} />
                  <XAxis dataKey="name" stroke="var(--color-text-muted)" tick={{ fontSize: 11 }} />
                  <YAxis stroke="var(--color-text-muted)" tick={{ fontSize: 11 }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="value" fill="#3b82f6" radius={[6, 6, 0, 0]} barSize={36}>
                    {stats.charts.auth_chart.map((entry, index) => (
                      <Cell key={`auth-${index}`} fill={entry.color || '#3b82f6'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-text-muted text-sm">No auth data available</div>
            )}
          </div>
        </div>

        {/* Top Targeted Users */}
        <div className="bg-surface rounded-2xl p-6 border border-surface-light shadow-sm">
          <h3 className="text-base font-bold text-text-main mb-1">Most Targeted User Accounts</h3>
          <p className="text-xs text-text-muted mb-4">Accounts with highest interaction or failed auth attempts</p>
          <div className="h-56">
            {stats?.charts?.top_users && stats.charts.top_users.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.charts.top_users} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-surface-light)" horizontal={false} />
                  <XAxis type="number" stroke="var(--color-text-muted)" tick={{ fontSize: 11 }} />
                  <YAxis dataKey="username" type="category" stroke="var(--color-text-muted)" width={90} tick={{ fontSize: 11 }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="count" fill="#10b981" radius={[0, 6, 6, 0]} barSize={18} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-text-muted text-sm">No user telemetry recorded</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

