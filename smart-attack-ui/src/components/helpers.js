/* ============================================================
   Shared helpers — severity / verdict / API
   ============================================================ */

// API 基础地址：本地开发默认 localhost:8888
// Docker 部署时可通过环境变量 VITE_API_BASE_URL=http://localhost:8888 覆盖
export const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8888';

export const STATUS_CLASS = (code) => {
  if (!code || code === 0) return 's0xx';
  if (code < 300) return 's2xx';
  if (code < 400) return 's3xx';
  if (code < 500) return 's4xx';
  return 's5xx';
};

export const VERDICT = (result) => {
  const text = (result.response_text || '').toLowerCase();
  if (
    result.status_code >= 200 &&
    result.status_code < 300 &&
    !text.includes('unauthorized') &&
    !text.includes('not found')
  ) {
    return { verdict: 'hit', label: '潜在命中' };
  }
  if (text.includes('error') || text.includes('exception')) {
    return { verdict: 'partial', label: '部分泄露' };
  }
  return { verdict: 'miss', label: '未命中' };
};

export const SEVERITY_COLOR = (type) => {
  const map = {
    bola: 'danger',
    idor: 'danger',
    privilege_escalation: 'danger',
    auth_bypass: 'danger',
    mass_assignment: 'warning',
    param_tampering: 'warning',
    logic_bypass: 'warning',
    info_leak: 'info',
  };
  return map[type] || 'info';
};

export const SEVERITY_CVSS_COLOR = (severity) => {
  const map = {
    critical: 'danger',
    high: 'danger',
    medium: 'warning',
    low: 'success',
    info: 'info',
  };
  return map[severity] || 'info';
};
