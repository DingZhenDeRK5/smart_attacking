import { useState } from 'react';
import { API_BASE } from './helpers';
import StatCard from './StatCard';
import ModelSelector from './ModelSelector';
import AuthConfig from './AuthConfig';
import ScanHistory from './ScanHistory';
import ScanProgress from './ScanProgress';

export default function Sidebar({
  isScanning, scanData, scanStatus, error,
  onScanStart, onSelectScan,
}) {
  const [targetUrl, setTargetUrl] = useState('http://127.0.0.1:5000/api/swagger.json');
  const [asyncMode, setAsyncMode] = useState(true);
  const [modelProvider, setModelProvider] = useState('deepseek');
  const [modelName, setModelName] = useState('deepseek-chat');
  const [customBaseUrl, setCustomBaseUrl] = useState('');
  const [customModel, setCustomModel] = useState('');
  const [authConfig, setAuthConfig] = useState({ type: 'none' });
  const [compareIds, setCompareIds] = useState([]);

  function handleModelChange({ provider, model, customBaseUrl, customModel }) {
    setModelProvider(provider);
    setModelName(model);
    setCustomBaseUrl(customBaseUrl || '');
    setCustomModel(customModel || '');
  }

  function handleScan() {
    const body = {
      url: targetUrl,
      mode: asyncMode ? 'async' : 'sync',
      model_provider: modelProvider,
      model_name: modelProvider === 'custom' ? customModel : modelName,
    };
    if (modelProvider === 'custom' && customBaseUrl) {
      body.custom_base_url = customBaseUrl;
    }
    if (authConfig.type !== 'none') {
      body.auth_config = authConfig;
    }
    onScanStart(body);
  }

  function handleCompareClick(scanId) {
    setCompareIds((prev) => {
      if (prev.includes(scanId)) return prev.filter((id) => id !== scanId);
      if (prev.length >= 2) return [prev[1], scanId];
      return [...prev, scanId];
    });
  }

  const data = scanData?.data || scanData;
  const phase1Count = scanData?.stats?.phase1_plan_count ?? data?.attack_plans?.length ?? 0;
  const phase1Exec = scanData?.stats?.phase1_executed ?? data?.execution_results?.length ?? 0;
  const phase2Count = scanData?.stats?.phase2_plan_count ?? data?.followup_plans?.length ?? 0;
  const phase2Exec = scanData?.stats?.phase2_executed ?? data?.followup_execution?.length ?? 0;
  const hitCount = data?.execution_results
    ? data.execution_results.filter((r) => {
        const text = (r.response_text || '').toLowerCase();
        return r.status_code >= 200 && r.status_code < 300
          && !text.includes('unauthorized') && !text.includes('not found');
      }).length
    : 0;
  const assessment = data?.security_assessment || {};
  const vulnCount = assessment.vulnerabilities_found?.length
    ?? data?.result_analysis?.confirmed_vulnerabilities?.length
    ?? 0;
  const overallRating = assessment.overall_rating || 'unknown';
  const scanId = scanData?.scan_id || data?.scan_id || '';

  return (
    <aside className="sidebar">
      {/* Scan Control */}
      <div>
        <div className="sidebar-section-title">任务控制</div>
        <div className="control-group">
          <label className="control-label">目标 Swagger 地址</label>
          <div className="input-wrapper">
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://target:3000/api/swagger.json"
              disabled={isScanning}
            />
          </div>
        </div>

        {/* Async toggle */}
        <label className="control-group" style={{ flexDirection: 'row', alignItems: 'center', gap: 8, marginTop: 8 }}>
          <input
            type="checkbox"
            checked={asyncMode}
            onChange={(e) => setAsyncMode(e.target.checked)}
            disabled={isScanning}
          />
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>异步模式（后台执行，可关闭页面）</span>
        </label>

        <button className="btn btn-primary" onClick={handleScan} disabled={isScanning}>
          {isScanning ? (
            <>
              <span className="scan-spinner" style={{ width: 16, height: 16, borderWidth: 2 }} />
              AI 分析中…
            </>
          ) : (
            <>🚀 启动 AI 渗透扫描</>
          )}
        </button>

        {/* PDF Download */}
        {scanId && (
          <button
            className="btn btn-primary"
            style={{ marginTop: 8, background: 'var(--success)' }}
            onClick={() => window.open(`${API_BASE}/scans/${scanId}/report?format=pdf`, '_blank')}
          >
            📄 下载 PDF 报告
          </button>
        )}
      </div>

      {/* Model Selector */}
      <ModelSelector
        provider={modelProvider}
        model={modelName}
        customBaseUrl={customBaseUrl}
        customModel={customModel}
        onChange={handleModelChange}
        disabled={isScanning}
      />

      {/* Auth Config */}
      <AuthConfig onChange={setAuthConfig} disabled={isScanning} />

      {/* Async Progress */}
      {scanStatus && scanStatus.status !== 'completed' && (
        <div>
          <div className="sidebar-section-title">扫描进度</div>
          <ScanProgress status={scanStatus} />
        </div>
      )}

      {/* Phase Progress (sync mode) */}
      {!scanStatus && (
        <div>
          <div className="sidebar-section-title">扫描阶段</div>
          <div className="phase-legend">
            {[
              { key: 'fetch', label: '抓取 Swagger' },
              { key: 'analyze', label: 'AI 业务分析 + 攻击方案' },
              { key: 'attack', label: '并发攻击执行' },
              { key: 'evaluate', label: 'AI 响应评估 + 后续攻击' },
            ].map((phase) => (
              <div key={phase.key} className="phase-step">
                <span className="phase-dot" />
                <span>{phase.label}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Stats */}
      {scanData && (
        <div>
          <div className="sidebar-section-title">扫描统计</div>
          <div className="stats-grid">
            <StatCard value={phase1Count + phase2Count} label="攻击方案" variant="accent" />
            <StatCard value={phase1Exec + phase2Exec} label="已执行" variant="accent" />
            <StatCard value={hitCount} label="潜在命中" variant={hitCount > 0 ? 'danger' : 'success'} />
            <StatCard value={vulnCount} label="确认漏洞" variant={vulnCount > 0 ? 'danger' : 'success'} />
          </div>
          <div style={{ marginTop: 16 }}>
            <div className="sidebar-section-title">安全评级</div>
            <div style={{
              fontSize: 36, fontWeight: 800,
              color: overallRating === 'high' ? 'var(--danger)'
                : overallRating === 'medium' ? 'var(--warning)'
                : 'var(--success)',
            }}>
              {overallRating.toUpperCase()}
            </div>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="remediation-box" style={{ color: 'var(--danger)', fontSize: 12 }}>
          {error}
        </div>
      )}

      {/* Scan History */}
      <ScanHistory
        onSelectScan={onSelectScan}
        onCompareScans={handleCompareClick}
        selectedIds={compareIds}
      />

      {/* Compare button */}
      {compareIds.length === 2 && (
        <button
          className="btn btn-primary"
          style={{ background: 'var(--warning)' }}
          onClick={() => onSelectScan?.(`compare:${compareIds[0]}:${compareIds[1]}`)}
        >
          🔍 对比两次扫描
        </button>
      )}
    </aside>
  );
}
