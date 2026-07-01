import { SEVERITY_COLOR } from './helpers';

export default function AttackPlans({ plans, title }) {
  if (!plans || plans.length === 0) return <p style={{ color: 'var(--text-muted)' }}>无攻击方案</p>;
  return (
    <div>
      {title && <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12 }}>{title}</h3>}
      {plans.map((p, i) => {
        const req = p.request || {};
        const method = (req.method || 'GET').toUpperCase();
        return (
          <div key={i} className="plan-card">
            <div className="plan-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className={`plan-method ${method}`}>{method}</span>
                <span className="plan-path">{req.url_path || '/'}</span>
              </div>
              <span className={`card-badge ${SEVERITY_COLOR(p.vulnerability_type)}`}>
                {p.vulnerability_type || 'unknown'}
              </span>
            </div>
            <div className="plan-reason">{p.reason}</div>
            <div className="plan-meta">
              {p.expected_normal_behavior && (
                <span className="plan-meta-item">预期正常: {p.expected_normal_behavior}</span>
              )}
              {p.exploit_indicator && (
                <span className="plan-meta-item">命中标志: {p.exploit_indicator}</span>
              )}
              {req.query_params && Object.keys(req.query_params).length > 0 && (
                <span className="plan-meta-item">参数: {JSON.stringify(req.query_params)}</span>
              )}
              {req.body && (
                <span className="plan-meta-item">Body: {JSON.stringify(req.body)}</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
