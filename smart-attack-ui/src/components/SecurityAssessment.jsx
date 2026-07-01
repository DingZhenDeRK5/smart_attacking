import { SEVERITY_CVSS_COLOR } from './helpers';

export default function SecurityAssessment({ assessment }) {
  if (!assessment || Object.keys(assessment).length === 0) return <p style={{ color: 'var(--text-muted)' }}>无评估结果</p>;
  const { overall_rating, vulnerabilities_found, remediation_advice } = assessment;
  return (
    <div>
      <div className="assessment-header">
        <span style={{ fontSize: 14, color: 'var(--text-muted)' }}>整体安全评级：</span>
        <span className={`rating-badge ${overall_rating || 'medium'}`}>
          {overall_rating ? overall_rating.toUpperCase() : 'UNKNOWN'}
        </span>
      </div>
      {vulnerabilities_found && vulnerabilities_found.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <h4 style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>发现的漏洞</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {vulnerabilities_found.map((v, i) => {
              const severity = v.severity || 'medium';
              const vulnType = v.vulnerability_type || v.vuln_type || 'unknown';
              const cvss = v.cvss_score != null ? `CVSS ${v.cvss_score}` : '';
              const owasp = v.owasp_category ? `OWASP ${v.owasp_category}` : '';
              return (
                <div key={i} style={{
                  padding: '12px 14px', borderRadius: 6,
                  background: 'var(--bg-root)', border: '1px solid var(--border)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span className={`card-badge ${SEVERITY_CVSS_COLOR(severity)}`}
                      style={{ fontSize: 10 }}>{severity.toUpperCase()}</span>
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                      {vulnType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                    </span>
                    {cvss && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{cvss}</span>}
                    {owasp && <span style={{ fontSize: 11, color: 'var(--accent)' }}>{owasp}</span>}
                  </div>
                  {v.endpoint && (
                    <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--text-secondary)', marginBottom: 4 }}>
                      {v.endpoint}
                    </div>
                  )}
                  <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {v.finding || v.description || JSON.stringify(v)}
                  </div>
                  {v.recommendation && (
                    <div style={{ fontSize: 12, color: 'var(--success)', marginTop: 4 }}>
                      💡 {v.recommendation}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
      {remediation_advice && (
        <div className="remediation-box">
          <strong>💡 修复建议：</strong>{remediation_advice}
        </div>
      )}
    </div>
  );
}
