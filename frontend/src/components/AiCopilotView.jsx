import { useState, useEffect, useRef, useCallback } from 'react';
import { copilotChat, getAiSummary } from '../services/api';
import { 
  Sparkles, 
  Send, 
  Bot, 
  User, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle,
  Zap
} from 'lucide-react';

const SUGGESTED_QUERIES = [
  "What happened in these logs?",
  "Which IP is most suspicious and why?",
  "Is this a brute-force attack?",
  "What defensive actions should I prioritize?",
  "Summarize all detected critical threats"
];

const AiCopilotView = () => {
  const [activeTab, setActiveTab] = useState('chat'); // 'chat' or 'summary'
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: "Hello! I am your AI SOC Copilot. I analyze ingested logs, track attacker progressions, and recommend incident containment playbooks. Ask me any question about the logs or click one of the quick prompts below."
    }
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  
  // Structured summary state
  const [summaryData, setSummaryData] = useState(null);
  const [summaryLoading, setSummaryLoading] = useState(false);

  const messagesEndRef = useRef(null);

  const loadAiSummary = useCallback(async () => {
    try {
      setSummaryLoading(true);
      const data = await getAiSummary();
      setSummaryData(data);
    } catch (err) {
      console.error('Failed to load AI summary', err);
    } finally {
      setSummaryLoading(false);
    }
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    if (activeTab === 'summary' && !summaryData) {
      loadAiSummary();
    }
  }, [activeTab, summaryData, loadAiSummary]);

  const handleSendMessage = async (queryText = null) => {
    const textToSend = queryText || inputQuery;
    if (!textToSend.trim() || chatLoading) return;

    const userMessage = { role: 'user', text: textToSend };
    setMessages(prev => [...prev, userMessage]);
    if (!queryText) setInputQuery('');
    setChatLoading(true);

    try {
      const response = await copilotChat(textToSend);
      const assistantText = response.answer || response.response || "No response generated from analysis engine.";
      
      setMessages(prev => [
        ...prev, 
        { 
          role: 'assistant', 
          text: assistantText,
          confirmed_evidence: response.confirmed_evidence,
          suspicious_indicators: response.suspicious_indicators,
          recommended_actions: response.recommended_actions || response.recommended_defensive_actions
        }
      ]);
    } catch (err) {
      setMessages(prev => [
        ...prev,
        { 
          role: 'assistant', 
          text: `⚠️ Query processing error: ${err.response?.data?.detail || err.message || 'Unable to connect to SOC AI engine.'}` 
        }
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  return (
    <div className="space-y-6 pb-12 max-w-6xl mx-auto flex flex-col h-[calc(100vh-7rem)]">
      {/* Header & Mode Switch */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 shrink-0">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-primary/10 border border-primary/20 rounded-xl text-primary">
              <Sparkles className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-text-main flex items-center gap-2">
                AI SOC Analyst Copilot
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  Dual AI / SOC Rules Engine
                </span>
              </h2>
              <p className="text-text-muted text-sm mt-0.5">
                Query log telemetry in natural language with strict distinction between evidence and hypothesis.
              </p>
            </div>
          </div>
        </div>

        {/* Tab Buttons */}
        <div className="flex bg-surface p-1 rounded-xl border border-surface-light shrink-0">
          <button
            onClick={() => setActiveTab('chat')}
            className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-colors ${
              activeTab === 'chat' 
                ? 'bg-primary text-black' 
                : 'text-text-muted hover:text-text-main'
            }`}
          >
            Interactive Chat
          </button>
          <button
            onClick={() => setActiveTab('summary')}
            className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-colors ${
              activeTab === 'summary' 
                ? 'bg-primary text-black' 
                : 'text-text-muted hover:text-text-main'
            }`}
          >
            Structured AI Briefing
          </button>
        </div>
      </div>

      {/* Main View Area */}
      {activeTab === 'chat' ? (
        <div className="flex-1 bg-surface rounded-2xl border border-surface-light flex flex-col overflow-hidden shadow-lg">
          {/* Messages Scroll Area */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            {messages.map((msg, idx) => (
              <div
                key={idx}
                className={`flex gap-3.5 max-w-4xl ${msg.role === 'user' ? 'ml-auto justify-end' : 'mr-auto justify-start'}`}
              >
                {msg.role === 'assistant' && (
                  <div className="w-8 h-8 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center text-primary shrink-0 mt-0.5">
                    <Bot className="w-4 h-4" />
                  </div>
                )}

                <div className={`rounded-2xl p-4 text-sm leading-relaxed ${
                  msg.role === 'user' 
                    ? 'bg-primary text-black font-medium max-w-xl shadow-sm' 
                    : 'bg-background/80 border border-surface-light text-text-main w-full'
                }`}>
                  <div className="whitespace-pre-wrap">{msg.text}</div>

                  {/* Evidence / Actions Pills if provided in structured response */}
                  {msg.confirmed_evidence && msg.confirmed_evidence.length > 0 && (
                    <div className="mt-4 pt-3 border-t border-surface-light space-y-1.5">
                      <div className="text-[11px] uppercase font-bold text-danger flex items-center gap-1.5">
                        <ShieldAlert className="w-3.5 h-3.5" /> Confirmed Evidence:
                      </div>
                      <ul className="text-xs text-text-muted space-y-1 pl-3 list-disc">
                        {msg.confirmed_evidence.map((ev, i) => (
                          <li key={i}>{ev}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {msg.recommended_actions && msg.recommended_actions.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-surface-light space-y-1.5">
                      <div className="text-[11px] uppercase font-bold text-emerald-400 flex items-center gap-1.5">
                        <CheckCircle className="w-3.5 h-3.5" /> Recommended SOC Actions:
                      </div>
                      <ul className="text-xs text-text-muted space-y-1 pl-3 list-disc">
                        {msg.recommended_actions.map((act, i) => (
                          <li key={i}>{typeof act === 'string' ? act : act.action || act.title}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {msg.role === 'user' && (
                  <div className="w-8 h-8 rounded-xl bg-surface-light border border-surface-light flex items-center justify-center text-text-main shrink-0 mt-0.5">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))}

            {chatLoading && (
              <div className="flex gap-3.5 items-center mr-auto">
                <div className="w-8 h-8 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center text-primary shrink-0 animate-pulse">
                  <Bot className="w-4 h-4" />
                </div>
                <div className="bg-background/80 border border-surface-light rounded-2xl px-4 py-3 text-xs text-text-muted flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-primary animate-ping"></div>
                  <span>Analyzing log patterns and synthesizing intelligence...</span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompts Pills */}
          <div className="px-6 py-2 border-t border-surface-light/40 bg-surface/50 overflow-x-auto flex gap-2">
            {SUGGESTED_QUERIES.map((q, idx) => (
              <button
                key={idx}
                onClick={() => handleSendMessage(q)}
                disabled={chatLoading}
                className="px-3 py-1 rounded-full bg-background border border-surface-light hover:border-primary/40 text-[11px] text-text-muted hover:text-text-main whitespace-nowrap transition-colors flex items-center gap-1 shrink-0"
              >
                <Zap className="w-2.5 h-2.5 text-primary" />
                {q}
              </button>
            ))}
          </div>

          {/* Input Bar */}
          <div className="p-4 border-t border-surface-light bg-surface flex items-center gap-3">
            <input
              type="text"
              placeholder="Ask the SOC Copilot anything about the logs or threat landscape..."
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSendMessage();
                }
              }}
              disabled={chatLoading}
              className="flex-1 bg-background border border-surface-light rounded-xl px-4 py-2.5 text-sm text-text-main focus:outline-none focus:border-primary/50"
            />

            <button
              onClick={() => handleSendMessage()}
              disabled={chatLoading || !inputQuery.trim()}
              className="p-2.5 rounded-xl bg-primary text-black font-bold hover:bg-primary-hover transition-colors disabled:opacity-40"
              aria-label="Send Query"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
        </div>
      ) : (
        /* Structured AI Briefing Tab */
        <div className="flex-1 bg-surface rounded-2xl border border-surface-light p-6 overflow-y-auto space-y-6">
          {summaryLoading ? (
            <div className="p-12 text-center text-text-muted animate-pulse">
              Synthesizing structured SOC assessment...
            </div>
          ) : !summaryData ? (
            <div className="p-12 text-center text-text-muted">
              <Sparkles className="w-10 h-10 mx-auto mb-2 text-surface-light" />
              <p className="text-base font-medium">No intelligence summary available</p>
              <button 
                onClick={loadAiSummary}
                className="mt-3 px-4 py-2 bg-primary text-black font-bold text-xs rounded-xl"
              >
                Generate Summary Now
              </button>
            </div>
          ) : (
            <div className="space-y-6 max-w-4xl mx-auto">
              {/* Executive Summary Card */}
              <div className="bg-background rounded-2xl border border-surface-light p-6 space-y-3">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-primary">
                  <Sparkles className="w-4 h-4" /> Executive Assessment
                </div>
                <p className="text-sm text-text-main leading-relaxed">
                  {summaryData.executive_summary || 'Logs analyzed with no critical breaches recorded.'}
                </p>
              </div>

              {/* Grid: Confirmed Evidence vs Suspicious Indicators */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-background rounded-2xl border border-surface-light p-5 space-y-3">
                  <div className="text-xs font-bold uppercase tracking-wider text-danger flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4" /> Confirmed Evidence
                  </div>
                  <ul className="space-y-2 text-xs text-text-muted">
                    {summaryData.confirmed_evidence?.length > 0 ? (
                      summaryData.confirmed_evidence.map((item, idx) => (
                        <li key={idx} className="flex items-start gap-2 bg-surface-light/30 p-2.5 rounded-lg border border-surface-light">
                          <span className="w-1.5 h-1.5 rounded-full bg-danger shrink-0 mt-1"></span>
                          <span>{item}</span>
                        </li>
                      ))
                    ) : (
                      <li className="italic">No confirmed compromise signatures found.</li>
                    )}
                  </ul>
                </div>

                <div className="bg-background rounded-2xl border border-surface-light p-5 space-y-3">
                  <div className="text-xs font-bold uppercase tracking-wider text-warning flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" /> Suspicious Indicators
                  </div>
                  <ul className="space-y-2 text-xs text-text-muted">
                    {summaryData.suspicious_indicators?.length > 0 ? (
                      summaryData.suspicious_indicators.map((item, idx) => (
                        <li key={idx} className="flex items-start gap-2 bg-surface-light/30 p-2.5 rounded-lg border border-surface-light">
                          <span className="w-1.5 h-1.5 rounded-full bg-warning shrink-0 mt-1"></span>
                          <span>{item}</span>
                        </li>
                      ))
                    ) : (
                      <li className="italic">No abnormal patterns detected.</li>
                    )}
                  </ul>
                </div>
              </div>

              {/* Potential Impact */}
              {summaryData.potential_impact && (
                <div className="bg-background rounded-2xl border border-surface-light p-5 space-y-2">
                  <div className="text-xs font-bold uppercase tracking-wider text-text-muted">
                    Potential Business & Security Impact
                  </div>
                  <p className="text-xs text-text-main leading-relaxed">
                    {summaryData.potential_impact}
                  </p>
                </div>
              )}

              {/* Recommended SOC Playbook */}
              {(summaryData.recommended_actions || summaryData.recommended_defensive_actions)?.length > 0 && (
                <div className="bg-primary/5 border border-primary/20 rounded-2xl p-6 space-y-3">
                  <div className="text-xs font-bold uppercase tracking-wider text-primary flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" /> Recommended Playbook Actions
                  </div>
                  <div className="space-y-2">
                    {(summaryData.recommended_actions || summaryData.recommended_defensive_actions).map((act, idx) => (
                      <div key={idx} className="flex items-start gap-2.5 text-xs text-text-main">
                        <span className="w-4 h-4 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                          {idx + 1}
                        </span>
                        <span>{typeof act === 'string' ? act : act.action || act.title}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default AiCopilotView;
