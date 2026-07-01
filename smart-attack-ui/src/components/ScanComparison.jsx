import { useState, useEffect } from 'react';
import { API_BASE } from './helpers';

export default function ScanComparison({ scanIdA, scanIdB, onClose }) {
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!scanIdA || !scanIdB) return;
    setLoading(true);
    fetch(`${API_BASE}/scans/compare?a=${scanIdA}&b=${scanIdB}`)
      .then((r) => r.json())
      .then((d) => {
        if (d.success) setComparison(d);
        else setError(d.error);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [scanIdA, scanIdB]);

  if (loading) return <div className="scan-progress"><span className="scan-spinner" /> 加载对比数据…</div>;
  if (error) return <div style={{ color: 'var(--danger)', padding: 16 }}>对比失败: {error}</div>;
  if (!comparison) return null;

  const { scan_a, scan_b, comparison: comp } = comparison;

  return (
    <div className="comparison-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h3 style={{ fontSize: 16, color: 'var(--text-primary)', margin: 0 }}>扫描对比</h3>
        {onClose && (
          <button className="chip" onClick={onClose}>✕ 关闭</button>
        )}
      </div>

      {/* Rating change */}
      <div className="comparison-summary">
        <div className="comparison-card">
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>扫描 A</div>
          <div style={{ fontSize: 13, fontWeight: 600 }}>{scan_a.target_url}</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{new Date(scan_a.created_at).toLocaleDateString()}</div>
          <span className={`rating-badge-sm ${scan_a.overall_rating}`}>{scan_a.overall_rating?.toUpperCase()}</span>
        </div>
        <div style={{ fontSize: 24, color: 'var(--accent)', fontWeight: 700 }}>→</div>
        <div className="comparison-card">
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>扫描 B</div>
          <div style={{ fontSize: 13, fontWeight: 600 }}>{scan_b.target_url}</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{new Date(scan_b.created_at).toLocaleDateString()}</div>
          <span className={`rating-badge-sm ${scan_b.overall_rating}`}>{scan_b.overall_rating?.toUpperCase()}</span>
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>评级变化：</span>
        <span className={`card-badge ${comp.rating_change === 'unchanged' ? 'success' : 'warn'}`}>
          {comp.rating_change}
        </span>
      </div>

      {/* Diff lists */}
      <div style={{ marginTop: 16 }}>
        <h4 style={{ fontSize: 13, color: 'var(--danger)', marginBottom: 8 }}>
          🆕 新增漏洞 ({comp.new_vulnerabilities?.length || 0})
        </h4>
        {comp.new_vulnerabilities?.map((v, i) => (
          <div key={i} className="scan-item" style={{ borderLeft: '3px solid var(--danger)' }}>
            <span className={`card-badge danger`}>{v.vulnerability_type || v.vuln_type}</span>
            <span style={{ fontSize: 12, marginLeft: 8 }}>{v.finding || v.endpoint}</span>
          </div>
        ))}
        {(!comp.new_vulnerabilities || comp.new_vulnerabilities.length === 0) && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: 8 }}>无新增漏洞</div>
        )}
      </div>

      <div style={{ marginTop: 16 }}>
        <h4 style={{ fontSize: 13, color: 'var(--success)', marginBottom: 8 }}>
          ✅ 已修复漏洞 ({comp.fixed_vulnerabilities?.length || 0})
        </h4>
        {comp.fixed_vulnerabilities?.map((v, i) => (
          <div key={i} className="scan-item" style={{ borderLeft: '3px solid var(--success)' }}>
            <span className={`card-badge success`}>{v.vulnerability_type || v.vuln_type}</span>
            <span style={{ fontSize: 12, marginLeft: 8 }}>{v.finding || v.endpoint}</span>
          </div>
        ))}
        {(!comp.fixed_vulnerabilities || comp.fixed_vulnerabilities.length === 0) && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: 8 }}>无已修复漏洞</div>
        )}
      </div>

      <div style={{ marginTop: 16 }}>
        <h4 style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>
          ➖ 未变化漏洞 ({comp.unchanged_vulnerabilities?.length || 0})
        </h4>
        {(!comp.unchanged_vulnerabilities || comp.unchanged_vulnerabilities.length === 0) && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: 8 }}>无长期残留漏洞</div>
        )}
      </div>
    </div>
  );
}
