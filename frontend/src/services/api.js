import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_URL,
});

// Attach JWT token to requests if present
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('analyst_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Logs & Ingestion
export const uploadLogs = async (file) => {
  // Read file as base64 to ensure Cloud WAF (e.g. Render/Cloudflare) doesn't block cyberattack signatures (SQLi, XSS, Path Traversal) in logs
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const rawResult = String(reader.result || '');
        const base64Data = rawResult.includes(',') ? rawResult.split(',')[1] : rawResult;
        const response = await api.post('/logs/paste', {
          content: base64Data,
          filename: file.name,
          is_base64: true
        });
        resolve(response.data);
      } catch (err) {
        reject(err);
      }
    };
    reader.onerror = (error) => reject(error);
    reader.readAsDataURL(file);
  });
};

export const pasteLogs = async (content, filename = 'pasted_logs.txt') => {
  // Base64 encode pasted content to protect against WAF false positives
  const base64Content = btoa(unescape(encodeURIComponent(content)));
  const response = await api.post('/logs/paste', {
    content: base64Content,
    filename,
    is_base64: true
  });
  return response.data;
};

export const loadSampleLogs = async () => {
  const response = await api.post('/logs/sample');
  return response.data;
};

export const getLogs = async () => {
  const response = await api.get('/logs');
  return response.data;
};

export const searchLogs = async (params = {}) => {
  const response = await api.get('/logs/search', { params });
  return response.data;
};

export const getLogDetails = async (id) => {
  const response = await api.get(`/logs/${id}`);
  return response.data;
};

// Dashboard & Analytics
export const getDashboardStats = async () => {
  const response = await api.get('/dashboard');
  return response.data;
};

export const getAuthAnalytics = async () => {
  const response = await api.get('/dashboard/auth-analytics');
  return response.data;
};

// Alerts
export const getAlerts = async (params = {}) => {
  const response = await api.get('/alerts', { params });
  return response.data;
};

export const getAlertDetails = async (id) => {
  const response = await api.get(`/alerts/${id}`);
  return response.data;
};

export const updateAlertStatus = async (id, status) => {
  const response = await api.put(`/alerts/${id}/status`, { status });
  return response.data;
};

export const bulkUpdateAlertStatus = async (alertIds, status) => {
  const response = await api.post('/alerts/bulk-status', { alert_ids: alertIds, status });
  return response.data;
};

// Incidents & Timeline
export const getIncidents = async () => {
  const response = await api.get('/incidents');
  return response.data;
};

export const getIncidentDetails = async (id) => {
  const response = await api.get(`/incidents/${id}`);
  return response.data;
};

export const updateIncidentStatus = async (id, status) => {
  const response = await api.put(`/incidents/${id}/status`, { status });
  return response.data;
};

// IP Analysis
export const getIpAnalysis = async () => {
  const response = await api.get('/ips');
  return response.data;
};

export const getSingleIpProfile = async (ip) => {
  const response = await api.get(`/ips/${ip}`);
  return response.data;
};

// Custom Rules
export const getCustomRules = async () => {
  const response = await api.get('/rules');
  return response.data;
};

export const createCustomRule = async (ruleData) => {
  const response = await api.post('/rules', ruleData);
  return response.data;
};

export const updateCustomRule = async (id, ruleData) => {
  const response = await api.put(`/rules/${id}`, ruleData);
  return response.data;
};

export const toggleCustomRule = async (id) => {
  const response = await api.patch(`/rules/${id}/toggle`);
  return response.data;
};

export const deleteCustomRule = async (id) => {
  const response = await api.delete(`/rules/${id}`);
  return response.data;
};

// Reports
export const getReportSummary = async () => {
  const response = await api.get('/reports/summary');
  return response.data;
};

export const exportReportUrl = (format = 'json') => {
  return `${API_URL}/reports/export?format=${format}`;
};

// Analysis History
export const getHistory = async () => {
  const response = await api.get('/history');
  return response.data;
};

export const getSessionDetails = async (id) => {
  const response = await api.get(`/history/${id}`);
  return response.data;
};

export const deleteSession = async (id) => {
  const response = await api.delete(`/history/${id}`);
  return response.data;
};

// AI Copilot
export const copilotChat = async (question) => {
  const response = await api.post('/copilot/chat', { question });
  return response.data;
};

export const getAiSummary = async () => {
  const response = await api.get('/copilot/ai-summary');
  return response.data;
};

// Authentication
export const loginAnalyst = async (username, password) => {
  const response = await api.post('/auth/login', { username, password });
  if (response.data.access_token) {
    localStorage.setItem('analyst_token', response.data.access_token);
  }
  return response.data;
};

export const registerAnalyst = async (username, password, role = 'Analyst') => {
  const response = await api.post('/auth/register', { username, password, role });
  if (response.data.access_token) {
    localStorage.setItem('analyst_token', response.data.access_token);
  }
  return response.data;
};

export const getCurrentUser = async () => {
  const response = await api.get('/auth/me');
  return response.data;
};

export const logoutAnalyst = () => {
  localStorage.removeItem('analyst_token');
};

