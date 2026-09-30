import { useState, useEffect } from 'react';
import { getCustomRules, createCustomRule, toggleCustomRule, deleteCustomRule } from '../services/api';
import { 
  Sliders, 
  Plus, 
  Trash2, 
  ToggleLeft, 
  ToggleRight, 
  X 
} from 'lucide-react';

const SeverityBadge = ({ severity }) => {
  const colors = {
    CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
    HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    MEDIUM: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold border ${colors[severity] || colors.LOW}`}>
      {severity}
    </span>
  );
};

const CustomRulesView = () => {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState('');

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    field: 'message',
    operator: 'contains',
    pattern: '',
    threshold: 1,
    window_minutes: 5,
    severity: 'HIGH',
    threat_type: 'Custom Threat',
    action: 'ALERT'
  });

  const fetchRules = async () => {
    try {
      setLoading(true);
      const data = await getCustomRules();
      setRules(data);
    } catch (err) {
      console.error('Failed to load custom rules', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggle = async (id) => {
    try {
      const updated = await toggleCustomRule(id);
      setRules(rules.map(r => r.id === id ? { ...r, enabled: updated.enabled } : r));
    } catch (err) {
      console.error('Failed to toggle rule', err);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this custom detection rule?')) return;
    try {
      await deleteCustomRule(id);
      setRules(rules.filter(r => r.id !== id));
    } catch (err) {
      console.error('Failed to delete rule', err);
    }
  };

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    setFormError('');

    if (!formData.name.trim() || !formData.pattern.trim()) {
      setFormError('Rule name and match pattern are required.');
      return;
    }

    try {
      setSubmitting(true);
      const newRule = await createCustomRule({
        ...formData,
        field_name: formData.field,
        threshold: parseInt(formData.threshold, 10) || 1,
        window_minutes: parseInt(formData.window_minutes, 10) || 5,
        enabled: true
      });
      setRules([...rules, newRule]);
      setShowCreateModal(false);
      setFormData({
        name: '',
        description: '',
        field: 'message',
        operator: 'contains',
        pattern: '',
        threshold: 1,
        window_minutes: 5,
        severity: 'HIGH',
        threat_type: 'Custom Threat',
        action: 'ALERT'
      });
    } catch (err) {
      setFormError(err.response?.data?.detail || 'Failed to create rule.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-primary/10 border border-primary/20 rounded-xl text-primary">
              <Sliders className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-text-main">Custom Detection Rules</h2>
              <p className="text-text-muted text-sm mt-0.5">
                Define domain-specific regex and signature rules evaluated across all incoming log streams.
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-primary text-black font-bold text-sm hover:bg-primary-hover transition-colors shadow-sm self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" /> Create Custom Rule
        </button>
      </div>

      {/* Rules Table */}
      <div className="bg-surface rounded-2xl border border-surface-light overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-light/40 border-b border-surface-light text-text-muted text-xs uppercase tracking-wider">
                <th className="px-4 py-4 font-medium text-center w-14">S.No.</th>
                <th className="px-6 py-4 font-medium">Status</th>
                <th className="px-6 py-4 font-medium">Rule Name</th>
                <th className="px-6 py-4 font-medium">Target Field & Match</th>
                <th className="px-6 py-4 font-medium">Condition</th>
                <th className="px-6 py-4 font-medium">Severity</th>
                <th className="px-6 py-4 font-medium">Threat Type</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-light">
              {loading ? (
                <tr>
                  <td colSpan="8" className="px-6 py-12 text-center text-text-muted animate-pulse">
                    Loading custom detection rules...
                  </td>
                </tr>
              ) : rules.length === 0 ? (
                <tr>
                  <td colSpan="8" className="px-6 py-12 text-center text-text-muted">
                    <Sliders className="w-10 h-10 mx-auto mb-3 text-surface-light" />
                    <p className="text-base font-medium">No custom rules configured yet</p>
                    <p className="text-xs text-text-muted mt-1">
                      Click &ldquo;Create Custom Rule&rdquo; to build your first signature detection.
                    </p>
                  </td>
                </tr>
              ) : (
                rules.map((rule, idx) => (
                  <tr key={rule.id} className="hover:bg-surface-light/20 transition-colors">
                    <td className="px-4 py-4 text-center text-text-muted font-mono text-xs font-medium">
                      {idx + 1}
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => handleToggle(rule.id)}
                        className="flex items-center gap-1.5 focus:outline-none"
                        title={rule.enabled ? 'Click to disable rule' : 'Click to enable rule'}
                      >
                        {rule.enabled ? (
                          <ToggleRight className="w-6 h-6 text-primary" />
                        ) : (
                          <ToggleLeft className="w-6 h-6 text-text-muted" />
                        )}
                        <span className={`text-xs font-semibold ${rule.enabled ? 'text-primary' : 'text-text-muted'}`}>
                          {rule.enabled ? 'Active' : 'Disabled'}
                        </span>
                      </button>
                    </td>

                    <td className="px-6 py-4">
                      <div className="font-bold text-sm text-text-main">{rule.name}</div>
                      {rule.description && (
                        <div className="text-xs text-text-muted mt-0.5 line-clamp-1">{rule.description}</div>
                      )}
                    </td>

                    <td className="px-6 py-4">
                      <div className="font-mono text-xs">
                        <span className="text-cyan-400 bg-background px-1.5 py-0.5 rounded mr-1">
                          {rule.field_name || rule.field || 'message'}
                        </span>
                        <span className="text-text-muted">{rule.operator}</span>
                      </div>
                      <div className="font-mono text-xs text-primary-dark mt-1 truncate max-w-xs" title={rule.pattern}>
                        &quot;{rule.pattern}&quot;
                      </div>
                    </td>

                    <td className="px-6 py-4 text-xs font-mono text-text-muted">
                      {rule.threshold > 1 ? (
                        <span>&ge; {rule.threshold} hits / {rule.window_minutes}m</span>
                      ) : (
                        <span>Immediate (1 hit)</span>
                      )}
                    </td>

                    <td className="px-6 py-4">
                      <SeverityBadge severity={rule.severity} />
                    </td>

                    <td className="px-6 py-4 text-xs font-semibold text-text-main">
                      {rule.threat_type}
                    </td>

                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => handleDelete(rule.id)}
                        className="p-1.5 rounded-lg text-text-muted hover:text-danger hover:bg-danger/10 transition-colors"
                        title="Delete Rule"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Rule Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-surface-light rounded-2xl w-full max-w-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between p-6 border-b border-surface-light">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-primary/10 rounded-xl text-primary">
                  <Sliders className="w-5 h-5" />
                </div>
                <h3 className="text-lg font-bold text-text-main">Create Custom Detection Rule</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-text-muted hover:text-text-main p-1 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="p-6 space-y-4">
              {formError && (
                <div className="p-3 bg-danger/10 border border-danger/30 rounded-xl text-danger text-xs">
                  {formError}
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2">
                  <label className="block text-xs font-bold uppercase text-text-muted mb-1.5">Rule Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Detect Unauthorized Sudo To Root"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full px-3 py-2 bg-background border border-surface-light rounded-xl text-sm text-text-main focus:outline-none focus:border-primary/50"
                  />
                </div>

                <div className="col-span-2">
                  <label className="block text-xs font-bold uppercase text-text-muted mb-1.5">Description</label>
                  <input
                    type="text"
                    placeholder="Contextual explanation of what this rule catches"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    className="w-full px-3 py-2 bg-background border border-surface-light rounded-xl text-sm text-text-main focus:outline-none focus:border-primary/50"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold uppercase text-text-muted mb-1.5">Target Field</label>
                  <select
                    value={formData.field}
                    onChange={(e) => setFormData({ ...formData, field: e.target.value })}
                    className="w-full px-3 py-2 bg-background border border-surface-light rounded-xl text-sm text-text-main focus:outline-none focus:border-primary/50"
                  >
                    <option value="message">message</option>
                    <option value="raw_log">raw_log</option>
                    <option value="event_type">event_type</option>
                    <option value="source_ip">source_ip</option>
                    <option value="username">username</option>
                    <option value="status_code">status_code</option>
                    <option value="http_method">http_method</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-bold uppercase text-text-muted mb-1.5">Operator</label>
                  <select
                    value={formData.operator}
                    onChange={(e) => setFormData({ ...formData, operator: e.target.value })}
                    className="w-full px-3 py-2 bg-background border border-surface-light rounded-xl text-sm text-text-main focus:outline-none focus:border-primary/50"
                  >
                    <option value="contains">contains (substring)</option>
                    <option value="regex">regex (regular expression)</option>
                    <option value="equals">equals (exact match)</option>
                    <option value="startswith">startswith</option>
                  </select>
                </div>

                <div className="col-span-2">
                  <label className="block text-xs font-bold uppercase text-text-muted mb-1.5">Pattern to Match *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. sudo:\s+.*COMMAND=.*\/bin\/bash"
                    value={formData.pattern}
                    onChange={(e) => setFormData({ ...formData, pattern: e.target.value })}
                    className="w-full px-3 py-2 bg-background border border-surface-light rounded-xl text-sm font-mono text-text-main focus:outline-none focus:border-primary/50"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold uppercase text-text-muted mb-1.5">Threshold (Hits)</label>
                  <input
                    type="number"
                    min="1"
                    value={formData.threshold}
                    onChange={(e) => setFormData({ ...formData, threshold: e.target.value })}
                    className="w-full px-3 py-2 bg-background border border-surface-light rounded-xl text-sm text-text-main focus:outline-none focus:border-primary/50"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold uppercase text-text-muted mb-1.5">Window (Minutes)</label>
                  <input
                    type="number"
                    min="1"
                    value={formData.window_minutes}
                    onChange={(e) => setFormData({ ...formData, window_minutes: e.target.value })}
                    className="w-full px-3 py-2 bg-background border border-surface-light rounded-xl text-sm text-text-main focus:outline-none focus:border-primary/50"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold uppercase text-text-muted mb-1.5">Severity</label>
                  <select
                    value={formData.severity}
                    onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                    className="w-full px-3 py-2 bg-background border border-surface-light rounded-xl text-sm text-text-main focus:outline-none focus:border-primary/50"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-bold uppercase text-text-muted mb-1.5">Threat Category</label>
                  <input
                    type="text"
                    value={formData.threat_type}
                    onChange={(e) => setFormData({ ...formData, threat_type: e.target.value })}
                    placeholder="e.g. Privilege Escalation"
                    className="w-full px-3 py-2 bg-background border border-surface-light rounded-xl text-sm text-text-main focus:outline-none focus:border-primary/50"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-surface-light">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-xl bg-surface-light text-text-muted hover:text-text-main text-sm font-semibold transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2 rounded-xl bg-primary text-black font-bold text-sm hover:bg-primary-hover transition-colors disabled:opacity-50"
                >
                  {submitting ? 'Saving Rule...' : 'Deploy Detection Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default CustomRulesView;
