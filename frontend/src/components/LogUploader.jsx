import { useState, useRef } from 'react';
import { uploadLogs, pasteLogs, loadSampleLogs } from '../services/api';
import { 
  UploadCloud, 
  FileJson, 
  PlayCircle, 
  Loader2, 
  Clipboard, 
  AlertCircle, 
  CheckCircle2, 
  FileCode,
  Sparkles,
  Eye,
  ArrowRight
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024; // 25 MB

const LogUploader = () => {
  const [tab, setTab] = useState('upload'); // 'upload' | 'paste'
  const [file, setFile] = useState(null);
  const [pastedContent, setPastedContent] = useState('');
  const [pasteFilename, setPasteFilename] = useState('security_events.log');
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const fileInputRef = useRef(null);
  const navigate = useNavigate();

  const validateAndSetFile = (selectedFile) => {
    setError('');
    setSuccess('');
    setAnalysisResult(null);
    if (!selectedFile) return;

    // Validate size
    if (selectedFile.size > MAX_FILE_SIZE_BYTES) {
      setError(`File is too large (${(selectedFile.size / (1024 * 1024)).toFixed(1)} MB). Maximum supported size is 25 MB.`);
      setFile(null);
      return;
    }

    // Validate extension
    const allowed = ['.log', '.txt', '.csv', '.json'];
    const name = selectedFile.name.toLowerCase();
    const hasValidExt = allowed.some((ext) => name.endsWith(ext));
    if (!hasValidExt) {
      setError(`Invalid file format. Please upload .log, .txt, .csv, or .json files.`);
      setFile(null);
      return;
    }

    setFile(selectedFile);
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    setError('');
    setSuccess('');
    setAnalysisResult(null);
    try {
      const result = await uploadLogs(file);
      setAnalysisResult(result);
      setSuccess(`Analysis Complete: Ingested ${result.logs_count} logs and correlated ${result.incidents_count || 0} incidents.`);
    } catch (err) {
      const detail = err.response?.data?.detail || 'Failed to upload and process logs.';
      setError(detail);
    } finally {
      setLoading(false);
    }
  };

  const handlePasteSubmit = async () => {
    if (!pastedContent.trim()) {
      setError('Please paste log lines before analyzing.');
      return;
    }
    setLoading(true);
    setError('');
    setSuccess('');
    setAnalysisResult(null);
    try {
      const result = await pasteLogs(pastedContent, pasteFilename || 'manual_paste.log');
      setAnalysisResult(result);
      setSuccess(`Analysis Complete: Ingested ${result.logs_count} logs with ${result.threats_count || 0} threats detected.`);
    } catch (err) {
      const detail = err.response?.data?.detail || 'Failed to process pasted logs.';
      setError(detail);
    } finally {
      setLoading(false);
    }
  };

  const handleSample = async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    setAnalysisResult(null);
    try {
      const result = await loadSampleLogs();
      setAnalysisResult(result);
      setSuccess(`Loaded ${result.logs_count} scenario logs: Brute-Force -> Account Compromise -> Privilege Command -> Exfiltration.`);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to load sample scenario logs.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-black tracking-tight">Data Ingestion Engine</h2>
          <p className="text-text-muted text-sm mt-1">
            Ingest raw multi-format security logs (.log, .txt, .csv, .json) or paste telemetry for automated AI threat detection.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => navigate('/history')}
            className="px-4 py-2 bg-surface hover:bg-surface-light border border-surface-light rounded-xl text-xs font-semibold text-text-muted hover:text-text-main transition-colors"
          >
            View Ingestion History
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-surface-light gap-2">
        <button
          onClick={() => { setTab('upload'); setError(''); setSuccess(''); setAnalysisResult(null); }}
          className={`px-5 py-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all ${
            tab === 'upload'
              ? 'border-primary text-primary'
              : 'border-transparent text-text-muted hover:text-text-main'
          }`}
        >
          <UploadCloud className="w-4 h-4" />
          File Upload & Dropzone
        </button>
        <button
          onClick={() => { setTab('paste'); setError(''); setSuccess(''); setAnalysisResult(null); }}
          className={`px-5 py-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all ${
            tab === 'paste'
              ? 'border-primary text-primary'
              : 'border-transparent text-text-muted hover:text-text-main'
          }`}
        >
          <Clipboard className="w-4 h-4" />
          Manual Log Paste
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Ingestion Box (Span 2) */}
        <div className="lg:col-span-2 bg-surface rounded-2xl p-6 border border-surface-light shadow-xl relative overflow-hidden">
          {tab === 'upload' ? (
            <div className="space-y-4">
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                className={`border-2 border-dashed rounded-2xl p-10 flex flex-col items-center justify-center text-center transition-all cursor-pointer ${
                  isDragging
                    ? 'border-primary bg-primary/10 scale-[0.99]'
                    : file
                    ? 'border-primary/60 bg-surface-light/20'
                    : 'border-surface-light hover:border-primary/50 bg-background/40'
                }`}
                onClick={() => fileInputRef.current?.click()}
              >
                <div className={`p-4 rounded-2xl mb-4 shadow-sm ${file ? 'bg-primary/20 text-primary' : 'bg-surface text-primary'}`}>
                  {file ? <FileCode className="w-10 h-10 animate-bounce" /> : <UploadCloud className="w-10 h-10" />}
                </div>

                <input
                  type="file"
                  ref={fileInputRef}
                  className="hidden"
                  accept=".log,.csv,.txt,.json"
                  onChange={handleFileChange}
                />

                {file ? (
                  <div className="space-y-1">
                    <p className="text-base font-bold text-text-main">{file.name}</p>
                    <p className="text-xs text-primary font-mono font-medium">
                      {(file.size / 1024).toFixed(1)} KB &bull; Ready for Analysis
                    </p>
                    <p className="text-xs text-text-muted mt-2">Click or drag another file to replace</p>
                  </div>
                ) : (
                  <div className="space-y-1">
                    <p className="text-base font-bold text-text-main">
                      Drag and drop your log file here, or <span className="text-primary underline">browse</span>
                    </p>
                    <p className="text-xs text-text-muted">
                      Supports Linux auth, Windows Events, Apache/Nginx web logs, Firewall logs, CSV, and JSON (up to 25MB)
                    </p>
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between text-xs text-text-muted px-2">
                <span>Maximum file size: <strong>25 MB</strong></span>
                <span>Supported: <strong>.log, .txt, .csv, .json</strong></span>
              </div>

              <button
                onClick={handleUpload}
                disabled={!file || loading}
                className={`w-full py-3.5 rounded-xl font-bold flex items-center justify-center gap-2 transition-all ${
                  !file || loading
                    ? 'bg-surface-light text-text-muted cursor-not-allowed'
                    : 'bg-primary hover:bg-primary-dark text-background shadow-lg shadow-primary/25 cursor-pointer hover:scale-[1.01]'
                }`}
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <FileJson className="w-5 h-5" />}
                {loading ? 'Executing ML & Rule Detection Engine...' : 'Run Automated Threat Analysis'}
              </button>

              {/* Results Button directly below Run Automated Threat Analysis */}
              <button
                onClick={() => navigate('/dashboard')}
                disabled={!analysisResult}
                className={`w-full py-3.5 rounded-xl font-bold flex items-center justify-center gap-2 transition-all ${
                  !analysisResult
                    ? 'bg-surface-light/40 text-text-muted/40 border border-surface-light cursor-not-allowed'
                    : 'bg-emerald-500 hover:bg-emerald-400 text-black shadow-lg shadow-emerald-500/25 cursor-pointer hover:scale-[1.01]'
                }`}
              >
                <Eye className="w-5 h-5" />
                <span>{analysisResult ? 'View Analysis Results' : 'Results'}</span>
                {analysisResult && <ArrowRight className="w-4 h-4 ml-1" />}
              </button>

              {/* Results Preview Card */}
              {analysisResult && (
                <div className="p-4 rounded-xl bg-surface border border-emerald-500/30 space-y-3 animate-in fade-in">
                  <div className="flex items-center justify-between text-xs text-text-muted uppercase font-bold tracking-wider">
                    <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Analysis Complete
                    </span>
                    <span className="font-mono text-text-muted">Session ID #{analysisResult.analysis_id}</span>
                  </div>
                  <div className="grid grid-cols-4 gap-2 text-center">
                    <div className="bg-background/60 p-2.5 rounded-lg border border-surface-light">
                      <div className="text-[10px] text-text-muted uppercase">Logs</div>
                      <div className="text-base font-black text-text-main">{analysisResult.logs_count ?? 0}</div>
                    </div>
                    <div className="bg-background/60 p-2.5 rounded-lg border border-surface-light">
                      <div className="text-[10px] text-text-muted uppercase">Threats</div>
                      <div className="text-base font-black text-warning">{analysisResult.threats_count ?? 0}</div>
                    </div>
                    <div className="bg-background/60 p-2.5 rounded-lg border border-surface-light">
                      <div className="text-[10px] text-text-muted uppercase">Incidents</div>
                      <div className="text-base font-black text-danger">{analysisResult.incidents_count ?? 0}</div>
                    </div>
                    <div className="bg-background/60 p-2.5 rounded-lg border border-surface-light">
                      <div className="text-[10px] text-text-muted uppercase">Risk Score</div>
                      <div className="text-base font-black text-primary">{Math.round(analysisResult.overall_risk_score ?? 0)}/100</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-text-muted mb-1.5 uppercase">
                  Log Dataset Label / Filename
                </label>
                <input
                  type="text"
                  value={pasteFilename}
                  onChange={(e) => setPasteFilename(e.target.value)}
                  placeholder="e.g. auth_dump.log"
                  className="w-full px-4 py-2 bg-background border border-surface-light rounded-xl text-sm focus:outline-none focus:border-primary/50 text-text-main font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-text-muted mb-1.5 uppercase">
                  Paste Raw Logs (Plain Text, Syslog, JSON, or CSV)
                </label>
                <textarea
                  rows={9}
                  value={pastedContent}
                  onChange={(e) => setPastedContent(e.target.value)}
                  placeholder="Oct 10 13:45:22 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.105 port 54321 ssh2&#10;192.168.1.100 - admin [12/Sep/2026:14:32:10 +0000] &quot;GET /login?user=' OR '1'='1 HTTP/1.1&quot; 200 4521&#10;Event 4625, An account failed to log on..."
                  className="w-full p-4 bg-background border border-surface-light rounded-xl text-xs font-mono focus:outline-none focus:border-primary/50 text-text-main resize-none leading-relaxed"
                />
              </div>

              <button
                onClick={handlePasteSubmit}
                disabled={!pastedContent.trim() || loading}
                className={`w-full py-3.5 rounded-xl font-bold flex items-center justify-center gap-2 transition-all ${
                  !pastedContent.trim() || loading
                    ? 'bg-surface-light text-text-muted cursor-not-allowed'
                    : 'bg-primary hover:bg-primary-dark text-background shadow-lg shadow-primary/25 cursor-pointer hover:scale-[1.01]'
                }`}
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Sparkles className="w-5 h-5" />}
                {loading ? 'Analyzing Pasted Telemetry...' : 'Analyze Pasted Logs'}
              </button>

              {/* Results Button directly below Analyze Pasted Logs */}
              <button
                onClick={() => navigate('/dashboard')}
                disabled={!analysisResult}
                className={`w-full py-3.5 rounded-xl font-bold flex items-center justify-center gap-2 transition-all ${
                  !analysisResult
                    ? 'bg-surface-light/40 text-text-muted/40 border border-surface-light cursor-not-allowed'
                    : 'bg-emerald-500 hover:bg-emerald-400 text-black shadow-lg shadow-emerald-500/25 cursor-pointer hover:scale-[1.01]'
                }`}
              >
                <Eye className="w-5 h-5" />
                <span>{analysisResult ? 'View Analysis Results' : 'Results'}</span>
                {analysisResult && <ArrowRight className="w-4 h-4 ml-1" />}
              </button>

              {/* Results Preview Card */}
              {analysisResult && (
                <div className="p-4 rounded-xl bg-surface border border-emerald-500/30 space-y-3 animate-in fade-in">
                  <div className="flex items-center justify-between text-xs text-text-muted uppercase font-bold tracking-wider">
                    <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Analysis Complete
                    </span>
                    <span className="font-mono text-text-muted">Session ID #{analysisResult.analysis_id}</span>
                  </div>
                  <div className="grid grid-cols-4 gap-2 text-center">
                    <div className="bg-background/60 p-2.5 rounded-lg border border-surface-light">
                      <div className="text-[10px] text-text-muted uppercase">Logs</div>
                      <div className="text-base font-black text-text-main">{analysisResult.logs_count ?? 0}</div>
                    </div>
                    <div className="bg-background/60 p-2.5 rounded-lg border border-surface-light">
                      <div className="text-[10px] text-text-muted uppercase">Threats</div>
                      <div className="text-base font-black text-warning">{analysisResult.threats_count ?? 0}</div>
                    </div>
                    <div className="bg-background/60 p-2.5 rounded-lg border border-surface-light">
                      <div className="text-[10px] text-text-muted uppercase">Incidents</div>
                      <div className="text-base font-black text-danger">{analysisResult.incidents_count ?? 0}</div>
                    </div>
                    <div className="bg-background/60 p-2.5 rounded-lg border border-surface-light">
                      <div className="text-[10px] text-text-muted uppercase">Risk Score</div>
                      <div className="text-base font-black text-primary">{Math.round(analysisResult.overall_risk_score ?? 0)}/100</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Feedback messages */}
          {error && (
            <div className="mt-4 p-4 rounded-xl bg-danger/10 border border-danger/30 text-danger text-sm flex items-center gap-3 animate-in fade-in">
              <AlertCircle className="w-5 h-5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="mt-4 p-4 rounded-xl bg-primary/10 border border-primary/30 text-primary text-sm flex items-center gap-3 animate-in fade-in">
              <CheckCircle2 className="w-5 h-5 shrink-0" />
              <span>{success}</span>
            </div>
          )}
        </div>

        {/* Demo Attack Sequence Simulator (Span 1) */}
        <div className="bg-surface-light/30 rounded-2xl p-6 border border-surface-light flex flex-col justify-between relative overflow-hidden">
          <div className="space-y-4">
            <div className="p-3 bg-warning/10 text-warning w-fit rounded-xl">
              <PlayCircle className="w-8 h-8" />
            </div>

            <div>
              <h3 className="text-lg font-bold text-text-main mb-1">Pre-Built Attack Demo</h3>
              <p className="text-xs text-text-muted leading-relaxed">
                Experience the full end-to-end Blue Team workflow with a curated multi-stage cyber intrusion scenario.
              </p>
            </div>

            <div className="bg-background/60 rounded-xl p-3 border border-surface-light/50 space-y-2 text-xs font-mono">
              <div className="flex items-center gap-2 text-text-muted">
                <span className="text-primary font-bold">09:00</span>
                <span>Normal user logon</span>
              </div>
              <div className="flex items-center gap-2 text-warning">
                <span className="font-bold">09:20</span>
                <span>SSH brute force burst (x5)</span>
              </div>
              <div className="flex items-center gap-2 text-danger">
                <span className="font-bold">09:22</span>
                <span>Account Compromise login</span>
              </div>
              <div className="flex items-center gap-2 text-danger">
                <span className="font-bold">09:23</span>
                <span>PowerShell dropper execution</span>
              </div>
              <div className="flex items-center gap-2 text-purple-400">
                <span className="font-bold">09:25</span>
                <span>5.2GB data exfiltration</span>
              </div>
            </div>
          </div>

          <button
            onClick={handleSample}
            disabled={loading}
            className="mt-6 w-full py-3 bg-surface hover:bg-surface-light text-text-main border border-surface-light hover:border-warning/50 rounded-xl font-bold flex items-center justify-center gap-2 transition-all cursor-pointer group"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin text-warning" /> : <PlayCircle className="w-4 h-4 text-warning group-hover:scale-110 transition-transform" />}
            Simulate Attack Chain
          </button>

          {analysisResult && (
            <button
              onClick={() => navigate('/dashboard')}
              className="mt-3 w-full py-3 bg-emerald-500 hover:bg-emerald-400 text-black rounded-xl font-bold flex items-center justify-center gap-2 transition-all cursor-pointer shadow-md shadow-emerald-500/20 text-sm"
            >
              <Eye className="w-4 h-4" />
              <span>View Analysis Results</span>
              <ArrowRight className="w-4 h-4 ml-1" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default LogUploader;

