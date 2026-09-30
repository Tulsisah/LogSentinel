import { useState, useEffect, useCallback } from 'react';
import { getReportSummary, exportReportUrl } from '../services/api';
import { 
  FileText, 
  Printer, 
  Download, 
  AlertTriangle, 
  ShieldAlert, 
  CheckCircle2, 
  Calendar, 
  Sparkles
} from 'lucide-react';

const ReportsView = () => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchReport = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getReportSummary();
      setReport(data);
    } catch (err) {
      console.error('Failed to load report', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReport();
  }, [fetchReport]);

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadCsv = () => {
    window.open(exportReportUrl('csv'), '_blank');
  };

  const handleDownloadJson = () => {
    window.open(exportReportUrl('json'), '_blank');
  };

  if (loading) {
    return (
      <div className="p-12 text-center text-text-muted bg-surface rounded-2xl border border-surface-light animate-pulse">
        Generating comprehensive SOC executive report...
      </div>
    );
  }

  if (!report) {
    return (
      <div className="p-12 text-center text-text-muted bg-surface rounded-2xl border border-surface-light">
        <FileText className="w-12 h-12 mx-auto mb-3 text-surface-light" />
        <p className="text-lg font-medium text-text-main">No report data available</p>
        <p className="text-sm mt-1">Ingest logs to generate an executive intelligence summary.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-16 max-w-5xl mx-auto print:p-0 print:max-w-none">
      {/* Action Header - Hidden during print */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 print:hidden">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-primary/10 border border-primary/20 rounded-xl text-primary">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-text-main">Executive & Technical SOC Report</h2>
              <p className="text-text-muted text-sm mt-0.5">
                Comprehensive security posture analysis, confirmed evidence, and defensive playbooks.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadCsv}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-surface border border-surface-light hover:bg-surface-light text-xs font-semibold text-text-main transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
          <button
            onClick={handleDownloadJson}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-surface border border-surface-light hover:bg-surface-light text-xs font-semibold text-text-main transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> JSON
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-primary text-black font-bold text-xs hover:bg-primary-hover transition-colors shadow-sm"
          >
            <Printer className="w-3.5 h-3.5" /> Print to PDF
          </button>
        </div>
      </div>

      {/* Printable Report Document Container */}
      <div className="bg-surface border border-surface-light rounded-3xl p-8 sm:p-10 shadow-xl space-y-8 print:border-none print:shadow-none print:p-0 print:bg-white print:text-black">
        {/* Document Header */}
        <div className="border-b border-surface-light pb-6 flex flex-col sm:flex-row justify-between items-start sm:items-end gap-4 print:border-gray-300">
          <div>
            <div className="flex items-center gap-2 text-primary font-mono text-xs uppercase tracking-widest font-bold mb-1 print:text-emerald-700">
              <ShieldAlert className="w-4 h-4" /> AI SOC Defense Center
            </div>
            <h1 className="text-3xl font-black text-text-main print:text-black">
              Incident Response & Threat Posture Audit
            </h1>
            <div className="flex items-center gap-4 text-xs text-text-muted mt-2 print:text-gray-600">
              <span className="flex items-center gap-1"><Calendar className="w-3.5 h-3.5" /> Generated: {new Date(report.generated_at).toLocaleString()}</span>
              <span>•</span>
              <span>Analyst Classification: Tier-2 Confidential</span>
            </div>
          </div>

          <div className="bg-background border border-surface-light px-5 py-3 rounded-2xl text-center print:border-gray-300 print:bg-gray-50">
            <div className="text-[10px] uppercase font-bold text-text-muted tracking-wider print:text-gray-500">
              Overall Threat Score
            </div>
            <div className={`text-3xl font-black ${
              report.metrics?.overall_risk_score >= 70 ? 'text-danger print:text-red-600' :
              report.metrics?.overall_risk_score >= 40 ? 'text-warning print:text-yellow-600' :
              'text-primary print:text-emerald-600'
            }`}>
              {Math.round(report.metrics?.overall_risk_score || 0)}<span className="text-sm font-normal text-text-muted">/100</span>
            </div>
          </div>
        </div>

        {/* Executive Summary Section */}
        <section className="space-y-3">
          <h2 className="text-base font-bold uppercase tracking-wider text-primary flex items-center gap-2 print:text-emerald-700">
            <Sparkles className="w-4 h-4" /> 1. Executive Summary
          </h2>
          <div className="bg-background/60 p-5 rounded-2xl border border-surface-light text-text-main text-sm leading-relaxed print:bg-gray-50 print:border-gray-200 print:text-gray-800">
            {report.executive_summary || 'Analysis of log telemetry indicates active reconnaissance and brute-force intrusion attempts. Timely defensive measures are recommended.'}
          </div>
        </section>

        {/* Key Metrics Grid */}
        <section className="space-y-3">
          <h2 className="text-base font-bold uppercase tracking-wider text-text-muted print:text-gray-700">
            2. High-Level Telemetry Metrics
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-background p-4 rounded-2xl border border-surface-light print:border-gray-200 print:bg-gray-50">
              <div className="text-xs text-text-muted uppercase print:text-gray-600">Total Logs Analyzed</div>
              <div className="text-2xl font-black text-text-main mt-1 print:text-black">
                {report.metrics?.total_logs?.toLocaleString() || 0}
              </div>
            </div>
            <div className="bg-background p-4 rounded-2xl border border-surface-light print:border-gray-200 print:bg-gray-50">
              <div className="text-xs text-text-muted uppercase print:text-gray-600">Correlated Incidents</div>
              <div className="text-2xl font-black text-danger mt-1 print:text-red-600">
                {report.metrics?.total_incidents || 0}
              </div>
            </div>
            <div className="bg-background p-4 rounded-2xl border border-surface-light print:border-gray-200 print:bg-gray-50">
              <div className="text-xs text-text-muted uppercase print:text-gray-600">Security Alerts</div>
              <div className="text-2xl font-black text-warning mt-1 print:text-yellow-600">
                {report.metrics?.total_alerts || 0}
              </div>
            </div>
            <div className="bg-background p-4 rounded-2xl border border-surface-light print:border-gray-200 print:bg-gray-50">
              <div className="text-xs text-text-muted uppercase print:text-gray-600">Critical Threats</div>
              <div className="text-2xl font-black text-danger mt-1 print:text-red-600">
                {report.metrics?.critical_threats || 0}
              </div>
            </div>
          </div>
        </section>

        {/* Evidence vs Suspicious Indicators Split */}
        <section className="space-y-3">
          <h2 className="text-base font-bold uppercase tracking-wider text-text-muted print:text-gray-700">
            3. Detailed Forensic Findings
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Confirmed Evidence */}
            <div className="bg-background p-5 rounded-2xl border border-surface-light space-y-3 print:border-gray-200 print:bg-gray-50">
              <div className="flex items-center gap-2 text-danger font-bold text-sm uppercase tracking-wider">
                <ShieldAlert className="w-4 h-4" /> Confirmed Evidence
              </div>
              <p className="text-xs text-text-muted">Verified unauthorized activity and direct signature triggers:</p>
              <ul className="space-y-2 text-xs text-text-main print:text-gray-800">
                {report.confirmed_evidence?.length > 0 ? (
                  report.confirmed_evidence.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2 bg-surface-light/40 p-2.5 rounded-lg border border-surface-light">
                      <span className="w-1.5 h-1.5 rounded-full bg-danger shrink-0 mt-1.5"></span>
                      <span>{item}</span>
                    </li>
                  ))
                ) : (
                  <li className="text-text-muted italic">No definitive compromise confirmed.</li>
                )}
              </ul>
            </div>

            {/* Suspicious Indicators */}
            <div className="bg-background p-5 rounded-2xl border border-surface-light space-y-3 print:border-gray-200 print:bg-gray-50">
              <div className="flex items-center gap-2 text-warning font-bold text-sm uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4" /> Suspicious Indicators
              </div>
              <p className="text-xs text-text-muted">Behavioral anomalies and abnormal event distributions:</p>
              <ul className="space-y-2 text-xs text-text-main print:text-gray-800">
                {report.suspicious_indicators?.length > 0 ? (
                  report.suspicious_indicators.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2 bg-surface-light/40 p-2.5 rounded-lg border border-surface-light">
                      <span className="w-1.5 h-1.5 rounded-full bg-warning shrink-0 mt-1.5"></span>
                      <span>{item}</span>
                    </li>
                  ))
                ) : (
                  <li className="text-text-muted italic">No anomalous indicators logged.</li>
                )}
              </ul>
            </div>
          </div>
        </section>

        {/* Potential Impact */}
        {report.potential_impact && (
          <section className="space-y-3">
            <h2 className="text-base font-bold uppercase tracking-wider text-text-muted print:text-gray-700">
              4. Potential Business & System Impact
            </h2>
            <div className="bg-background p-5 rounded-2xl border border-surface-light text-xs text-text-main leading-relaxed print:border-gray-200 print:bg-gray-50 print:text-gray-800">
              {report.potential_impact}
            </div>
          </section>
        )}

        {/* Top Suspicious IPs Table */}
        {report.top_suspicious_ips?.length > 0 && (
          <section className="space-y-3">
            <h2 className="text-base font-bold uppercase tracking-wider text-text-muted print:text-gray-700">
              5. Top Threat Actors & Adversary IPs
            </h2>
            <div className="overflow-x-auto border border-surface-light rounded-2xl print:border-gray-200">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-background/80 border-b border-surface-light text-text-muted uppercase">
                    <th className="px-4 py-3">IP Address</th>
                    <th className="px-4 py-3">Classification</th>
                    <th className="px-4 py-3">Total Events</th>
                    <th className="px-4 py-3">Failed Logins</th>
                    <th className="px-4 py-3">Risk Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-light print:divide-gray-200">
                  {report.top_suspicious_ips.map((ip, idx) => (
                    <tr key={idx} className="hover:bg-surface-light/20">
                      <td className="px-4 py-3 font-mono font-bold text-primary-dark">{ip.ip}</td>
                      <td className="px-4 py-3">{ip.reputation_label}</td>
                      <td className="px-4 py-3">{ip.request_count}</td>
                      <td className="px-4 py-3 text-danger font-bold">{ip.failed_logins}</td>
                      <td className="px-4 py-3 font-bold text-danger">{Math.round(ip.risk_score)}/100</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* Recommended Actions / Playbook Steps */}
        <section className="space-y-3">
          <h2 className="text-base font-bold uppercase tracking-wider text-primary flex items-center gap-2 print:text-emerald-700">
            <CheckCircle2 className="w-4 h-4" /> 6. SOC Remediation Playbook
          </h2>
          <div className="bg-primary/5 border border-primary/20 rounded-2xl p-6 space-y-3 print:bg-gray-50 print:border-gray-300">
            {report.recommended_actions?.length > 0 ? (
              report.recommended_actions.map((act, idx) => (
                <div key={idx} className="flex items-start gap-3 text-xs text-text-main print:text-gray-800">
                  <div className="w-5 h-5 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5 print:bg-emerald-100 print:text-emerald-800">
                    {idx + 1}
                  </div>
                  <div>
                    <span className="font-bold">{act.title || act.step || `Step ${idx + 1}`}: </span>
                    <span className="text-text-muted print:text-gray-600">{act.description || act.action || act}</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-xs text-text-muted">No immediate remediation actions required.</div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
};

export default ReportsView;
