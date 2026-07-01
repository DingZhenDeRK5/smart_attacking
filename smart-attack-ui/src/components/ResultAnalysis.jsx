export default function ResultAnalysis({ analysis }) {
  if (!analysis || Object.keys(analysis).length === 0) return <p style={{ color: 'var(--text-muted)' }}>无分析结果</p>;
  const { summary, defense_level, per_attack_analysis, confirmed_vulnerabilities, information_leaked } = analysis;
  return (
    <div>
      {summary && (
        <div className="remediation-box" style={{ marginTop: 0, marginBottom: 16 }}>
          <strong>总结：</strong>{summary}
        </div>
      )}
      {defense_level && (
        <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>防御水平：</span>
          <span className={`card-badge ${defense_level === 'strong' ? 'success' : defense_level === 'moderate' ? 'warn' : 'danger'}`}>
            {defense_level.toUpperCase()}
          </span>
        </div>
      )}
      {per_attack_analysis && per_attack_analysis.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <h4 style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>逐项分析</h4>
          {per_attack_analysis.map((a, i) => (
            <div key={i} style={{
              padding: '8px 12px', marginBottom: 6, borderRadius: 6,
              background: 'var(--bg-root)', border: '1px solid var(--border)',
              display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 13,
            }}>
              <span>{a.verdict === 'success' ? '✅' : a.verdict === 'partial' ? '⚠️' : '❌'}</span>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>轮次 {a.round}：</span>
                <span style={{ color: 'var(--text-primary)' }}>{a.finding || a.why || ''}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {confirmed_vulnerabilities && confirmed_vulnerabilities.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <h4 style={{ fontSize: 13, color: 'var(--danger)', marginBottom: 8 }}>🔴 已确认漏洞</h4>
          <ul className="vuln-confirmed-list">
            {confirmed_vulnerabilities.map((v, i) => (
              <li key={i}><span>✕</span> {typeof v === 'string' ? v : v.finding || v.description || JSON.stringify(v)}</li>
            ))}
          </ul>
        </div>
      )}
      {information_leaked && information_leaked.length > 0 && (
        <div>
          <h4 style={{ fontSize: 13, color: 'var(--warning)', marginBottom: 8 }}>📋 信息泄露</h4>
          <ul className="vuln-confirmed-list">
            {information_leaked.map((v, i) => (
              <li key={i} style={{ color: 'var(--text-secondary)' }}>
                <span>▸</span> {typeof v === 'string' ? v : JSON.stringify(v)}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
