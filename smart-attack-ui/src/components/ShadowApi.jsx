import { useState } from 'react';
import { API_BASE } from './helpers';

const SAMPLE_HAR = JSON.stringify({
  log: {
    entries: [
      // ===== 真实已声明的端点（流量中有、文档中也有）=====
      { request: { method: "GET", url: "http://target:3000/api/users/profile" } },
      { request: { method: "POST", url: "http://target:3000/api/orders/update?order_id=12345&new_address=test" } },
      { request: { method: "POST", url: "http://target:3000/api/users/register" } },
      { request: { method: "GET", url: "http://target:3000/api/orders/detail?order_id=1" } },
      { request: { method: "GET", url: "http://target:3000/api/orders/detail?order_id=2" } },
      { request: { method: "GET", url: "http://target:3000/api/users/all" } },
      { request: { method: "POST", url: "http://target:3000/api/users/login" } },
      { request: { method: "POST", url: "http://target:3000/api/orders/create" } },
      // ===== 影子 API（流量中出现但文档中未声明）=====
      { request: { method: "GET", url: "http://target:3000/api/admin/config" } },
      { request: { method: "POST", url: "http://target:3000/api/admin/deleteUser?id=admin" } },
      { request: { method: "GET", url: "http://target:3000/api/debug/status" } },
      { request: { method: "POST", url: "http://target:3000/api/internal/migrate" } },
    ],
  },
}, null, 2);

const RISK_BADGE = (risk) => {
  const map = {
    critical: { cls: 'danger', label: '严重' },
    high: { cls: 'danger', label: '高危' },
    medium: { cls: 'warn', label: '中危' },
    low: { cls: 'success', label: '低危' },
  };
  const m = map[risk] || { cls: 'info', label: risk };
  return <span className={`card-badge ${m.cls}`}>{m.label}</span>;
};

export default function ShadowApi({ onNavigate }) {
  const [swaggerUrl, setSwaggerUrl] = useState('http://127.0.0.1:3000/api/swagger.json');
  const [trafficLog, setTrafficLog] = useState('');
  const [trafficFormat, setTrafficFormat] = useState('auto');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [scanning, setScanning] = useState(false);

  function loadSample() {
    setTrafficLog(SAMPLE_HAR);
    setTrafficFormat('har');
  }

  async function handleDetect() {
    if (!swaggerUrl || !trafficLog.trim()) {
      setError('请填写 Swagger 地址和流量日志');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/shadow_api/detect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          swagger_url: swaggerUrl,
          traffic_log: trafficLog,
          traffic_format: trafficFormat,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setResult(data);
      } else {
        setError(data.error || '检测失败');
      }
    } catch (e) {
      setError(`请求失败：${e.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function handleScanShadow() {
    if (!result || result.shadow_apis.length === 0) return;
    setScanning(true);

    // 推导 base_url
    const baseUrl = swaggerUrl.replace(/\/api\/.*$/, '') || swaggerUrl.split('/api/')[0];

    try {
      const res = await fetch(`${API_BASE}/shadow_api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          base_url: baseUrl,
          shadow_apis: result.shadow_apis.map((a) => ({
            method: a.method,
            path: a.raw_path || a.path,
          })),
        }),
      });
      const data = await res.json();
      if (data.success) {
        setError(null);
        // 跳转到扫描页面，传入 scan_id 自动开始轮询
        onNavigate?.('scanner', data.scan_id);
      } else {
        setError(data.error || '扫描启动失败');
      }
    } catch (e) {
      setError(`请求失败：${e.message}`);
    } finally {
      setScanning(false);
    }
  }

  const stats = result?.stats;

  return (
    <div className="shadow-api-page">
      <h1 className="shadow-hero-title">🕵️ 影子 API 发现</h1>
      <p className="shadow-hero-sub">
        通过对比真实流量日志与 Swagger/OpenAPI 文档，找出未经登记、未受安全审查的"影子 API"，
        并自动进行渗透测试。
      </p>

      {/* Input Area */}
      <div className="shadow-input-row">
        <div className="shadow-input-card">
          <div className="dash-chart-title">📄 Swagger 文档地址</div>
          <input
            type="text"
            className="model-select-input"
            value={swaggerUrl}
            onChange={(e) => setSwaggerUrl(e.target.value)}
            placeholder="http://target:3000/api/swagger.json"
            disabled={loading}
          />
        </div>
        <div className="shadow-input-card" style={{ flex: 2 }}>
          <div className="dash-chart-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>📊 流量日志</span>
            <button className="chip" onClick={loadSample} disabled={loading} style={{ fontSize: 10 }}>
              📋 填入示例
            </button>
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <select
              className="model-select"
              value={trafficFormat}
              onChange={(e) => setTrafficFormat(e.target.value)}
              disabled={loading}
              style={{ width: 160, padding: '6px 10px', fontSize: 12 }}
            >
              <option value="auto">自动检测格式</option>
              <option value="har">HAR (浏览器导出)</option>
              <option value="json">JSON 数组</option>
              <option value="urls">纯文本 URL 列表</option>
            </select>
          </div>
          <textarea
            className="shadow-traffic-input"
            value={trafficLog}
            onChange={(e) => setTrafficLog(e.target.value)}
            placeholder={`支持格式：
  • HAR 1.2 — 浏览器 DevTools → Network → Export HAR
  • JSON 数组 — [{"method": "GET", "path": "/api/users"}, ...]
  • 纯文本 — 每行一个：POST /api/admin/delete

点击「填入示例」查看完整 HAR 格式`}
            disabled={loading}
            rows={12}
          />
        </div>
      </div>

      {/* Detect button */}
      <div style={{ display: 'flex', gap: 12, justifyContent: 'center', marginTop: 16, marginBottom: 24 }}>
        <button className="btn btn-primary" onClick={handleDetect} disabled={loading}
          style={{ padding: '12px 32px', fontSize: 15 }}>
          {loading ? (
            <><span className="scan-spinner" style={{ width: 16, height: 16, borderWidth: 2 }} /> 分析中…</>
          ) : (
            '🔍 开始检测影子 API'
          )}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="result-card" style={{ borderColor: 'var(--danger)', marginBottom: 16 }}>
          <div className="result-card-header" style={{ cursor: 'default' }}>
            <div className="card-title-group">
              <div className="card-icon" style={{ background: 'var(--danger-soft)' }}>❌</div>
              <div className="card-title" style={{ color: 'var(--danger)' }}>{error}</div>
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <>
          {/* Stats bar */}
          <div className="dash-hero-row" style={{ marginBottom: 24 }}>
            <div className="dash-hero-card">
              <div className="dash-hero-value" style={{ fontSize: 24 }}>{stats.swagger_count}</div>
              <div className="dash-hero-label">已声明 API</div>
            </div>
            <div className="dash-hero-card">
              <div className="dash-hero-value" style={{ fontSize: 24 }}>{stats.traffic_unique_count}</div>
              <div className="dash-hero-label">流量中唯一端点</div>
            </div>
            <div className="dash-hero-card" style={{ borderColor: 'var(--danger)' }}>
              <div className="dash-hero-value" style={{ fontSize: 24, color: 'var(--danger)' }}>{stats.shadow_count}</div>
              <div className="dash-hero-label">影子 API</div>
              <div className="dash-hero-trend up" style={{ color: 'var(--danger)' }}>{stats.shadow_rate} 未登记</div>
            </div>
            <div className="dash-hero-card">
              <div className="dash-hero-value" style={{ fontSize: 24, color: 'var(--success)' }}>{stats.documented_count}</div>
              <div className="dash-hero-label">合法 API (已登记)</div>
            </div>
          </div>

          {/* Shadow API table */}
          <div className="dash-chart-card" style={{ marginBottom: 16 }}>
            <div className="dash-chart-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>🚨 影子 API 列表 ({result.shadow_apis.length})</span>
              {result.shadow_apis.length > 0 && (
                <button
                  className="btn btn-primary"
                  onClick={handleScanShadow}
                  disabled={scanning}
                  style={{ padding: '8px 16px', fontSize: 12, background: 'var(--danger)', width: 'auto' }}
                >
                  {scanning ? '启动中…' : '⚡ 对影子 API 发起渗透扫描'}
                </button>
              )}
            </div>

            {result.shadow_apis.length === 0 ? (
              <div style={{ textAlign: 'center', padding: 24, color: 'var(--success)', fontSize: 14 }}>
                ✅ 未发现影子 API，所有流量端点均在文档中有登记。
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="execution-table">
                  <thead>
                    <tr>
                      <th>风险</th>
                      <th>方法</th>
                      <th>归一化路径</th>
                      <th>原始路径</th>
                      <th>说明</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.shadow_apis.map((api, i) => (
                      <tr key={i}>
                        <td>{RISK_BADGE(api.risk)}</td>
                        <td>
                          <span className={`plan-method ${api.method}`}>{api.method}</span>
                        </td>
                        <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-primary)' }}>
                          {api.path}
                        </td>
                        <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-muted)' }}>
                          {api.raw_path}
                        </td>
                        <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                          {api.note || ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Documented overlap */}
          {result.documented_apis.length > 0 && (
            <div className="dash-chart-card" style={{ marginBottom: 16 }}>
              <div className="dash-chart-title">
                ✅ 已登记 API ({result.documented_apis.length} 个与文档一致)
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {result.documented_apis.slice(0, 20).map((api, i) => (
                  <span key={i} style={{
                    fontFamily: 'monospace', fontSize: 11,
                    padding: '3px 8px', borderRadius: 4,
                    background: 'var(--success-soft)', color: 'var(--success)',
                  }}>
                    {api.method} {api.path}
                  </span>
                ))}
                {result.documented_apis.length > 20 && (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    … 还有 {result.documented_apis.length - 20} 个
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Only documented (zombie docs) */}
          {result.only_documented.length > 0 && (
            <div className="dash-chart-card">
              <div className="dash-chart-title">
                📝 仅文档声明但无流量 ({result.only_documented.length} 个可能废弃)
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {result.only_documented.slice(0, 15).map((api, i) => (
                  <span key={i} style={{
                    fontFamily: 'monospace', fontSize: 11,
                    padding: '3px 8px', borderRadius: 4,
                    background: 'var(--bg-root)', color: 'var(--text-muted)',
                    border: '1px solid var(--border)',
                  }}>
                    {api.method} {api.path}
                  </span>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
