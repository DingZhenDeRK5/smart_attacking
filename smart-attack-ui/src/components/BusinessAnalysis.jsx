export default function BusinessAnalysis({ analysis }) {
  if (!analysis || Object.keys(analysis).length === 0)
    return <p style={{ color: 'var(--text-muted)' }}>无分析数据</p>;
  const { domain, entities, relationships, auth_model, trust_assumptions, vulnerability_surface, attack_surface_summary } = analysis;
  return (
    <div className="analysis-grid">
      {domain && (
        <div className="analysis-item">
          <div className="analysis-item-label">业务领域</div>
          <div className="analysis-item-value">{domain}</div>
        </div>
      )}
      {auth_model && (
        <div className="analysis-item">
          <div className="analysis-item-label">权限模型</div>
          <div className="analysis-item-value">{auth_model}</div>
        </div>
      )}
      {entities && entities.length > 0 && (
        <div className="analysis-item">
          <div className="analysis-item-label">核心实体</div>
          <div>
            {entities.map((e, i) => (
              <span key={i} className="entity-tag">
                {e.name}
                <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{e.id_pattern}</span>
              </span>
            ))}
          </div>
        </div>
      )}
      {relationships && relationships.length > 0 && (
        <div className="analysis-item">
          <div className="analysis-item-label">实体关系</div>
          <div>
            {relationships.map((r, i) => (
              <div key={i} className="relationship-line">
                {r.from} <span style={{ color: 'var(--accent)' }}>—{r.type}→</span> {r.to}
              </div>
            ))}
          </div>
        </div>
      )}
      {trust_assumptions && trust_assumptions.length > 0 && (
        <div className="analysis-item">
          <div className="analysis-item-label">⚠️ 不安全信任假设</div>
          <div>
            {trust_assumptions.map((t, i) => (
              <div key={i} className="trust-assumption-item">
                <span>✕</span> {typeof t === 'string' ? t : t.description || JSON.stringify(t)}
              </div>
            ))}
          </div>
        </div>
      )}
      {vulnerability_surface && vulnerability_surface.length > 0 && (
        <div className="analysis-item full">
          <div className="analysis-item-label">攻击面测绘</div>
          <div>
            {vulnerability_surface.map((v, i) => (
              <div key={i} className="vuln-surface-item">
                <span className={`risk-tag ${v.risk ? v.risk.toLowerCase().replace('/', '_') : ''}`}>
                  {v.risk || 'RISK'}
                </span>
                <div>
                  <div style={{ color: 'var(--text-primary)', fontSize: 13, fontWeight: 600 }}>{v.endpoint}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{v.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      {attack_surface_summary && (
        <div className="analysis-item full">
          <div className="analysis-item-label">风险评估总结</div>
          <div className="analysis-item-value">{attack_surface_summary}</div>
        </div>
      )}
    </div>
  );
}
