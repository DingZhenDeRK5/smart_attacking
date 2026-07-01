import { useState, useEffect } from 'react';
import { API_BASE } from './helpers';

/* ============================================================
   Case Studies — 真实测试案例展示
   路演用：证明系统在真实靶场上发现了什么
   ============================================================ */

function SeverityDot({ severity }) {
  const colors = {
    critical: 'var(--danger)', high: 'var(--danger)',
    medium: 'var(--warning)', low: 'var(--success)', info: 'var(--info)',
  };
  return (
    <span style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: colors[severity] || colors.info,
      marginRight: 6, boxShadow: `0 0 6px ${colors[severity] || colors.info}`,
    }} />
  );
}

// 从真实扫描数据中提取漏洞列表
function extractVulns(scan) {
  const data = scan?.data || scan;
  const sa = data?.security_assessment || {};
  const ra = data?.result_analysis || {};

  // 优先用结构化漏洞数据
  let vulns = sa.vulnerabilities_found || [];
  if (vulns.length > 0) return vulns;

  // 兜底：从 result_analysis 取
  const confirmed = ra.confirmed_vulnerabilities || [];
  if (confirmed.length > 0) {
    return confirmed.map((v) =>
      typeof v === 'string' ? { finding: v, vulnerability_type: 'unknown', severity: 'medium' } : v
    );
  }
  return [];
}

// 从 result_analysis 取泄露信息
function extractLeaks(scan) {
  const data = scan?.data || scan;
  const ra = data?.result_analysis || {};
  return ra.information_leaked || [];
}

export default function CaseStudies() {
  const [realScans, setRealScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedReal, setExpandedReal] = useState(null);
  const [expandedDemo, setExpandedDemo] = useState(null);

  // 拉取真实扫描数据
  useEffect(() => {
    fetch(`${API_BASE}/scans?limit=10`)
      .then((r) => r.json())
      .then((d) => {
        if (d.success && d.scans) {
          const completed = d.scans.filter((s) => s.status === 'completed' || !s.status);
          Promise.all(
            completed.slice(0, 5).map((s) =>
              fetch(`${API_BASE}/scans/${s.scan_id}`)
                .then((r) => r.json())
                .then((d) => (d.success ? d.scan : null))
                .catch(() => null)
            )
          ).then((details) => {
            setRealScans(details.filter(Boolean));
            setLoading(false);
          });
        } else {
          setLoading(false);
        }
      })
      .catch(() => setLoading(false));
  }, []);

  // 统计
  const totalVulns = realScans.reduce((s, scan) => s + extractVulns(scan).length, 0);
  const totalAttacks = realScans.reduce((s, scan) => {
    const st = scan?.stats || {};
    return s + (st.phase1_executed || 0) + (st.phase2_executed || 0);
  }, 0);
  const totalPlans = realScans.reduce((s, scan) => {
    const st = scan?.stats || {};
    return s + (st.phase1_plan_count || 0) + (st.phase2_plan_count || 0);
  }, 0);
  const highRating = realScans.filter((scan) => {
    const data = scan?.data || scan;
    return data?.security_assessment?.overall_rating === 'high';
  }).length;

  return (
    <div className="casestudy-page">
      <h1 className="shadow-hero-title">📋 测试案例</h1>
      <p className="shadow-hero-sub">
        SmartAttack 已对靶场 API 完成多次自动化渗透测试，以下为真实扫描结果与漏洞发现。
      </p>

      {/* ======== 实时统计卡片 ======== */}
      {!loading && (
        <div className="dash-hero-row" style={{ marginBottom: 24 }}>
          <div className="dash-hero-card">
            <div className="dash-hero-value" style={{ fontSize: 24 }}>{realScans.length}</div>
            <div className="dash-hero-label">已完成真实扫描</div>
          </div>
          <div className="dash-hero-card">
            <div className="dash-hero-value" style={{ fontSize: 24 }}>{totalAttacks}</div>
            <div className="dash-hero-label">攻击请求执行</div>
          </div>
          <div className="dash-hero-card" style={{ borderColor: 'var(--danger)' }}>
            <div className="dash-hero-value" style={{ fontSize: 24, color: 'var(--danger)' }}>{totalVulns}</div>
            <div className="dash-hero-label">发现漏洞</div>
          </div>
          <div className="dash-hero-card" style={{ borderColor: highRating > 0 ? 'var(--danger)' : 'var(--success)' }}>
            <div className="dash-hero-value" style={{ fontSize: 24, color: highRating > 0 ? 'var(--danger)' : 'var(--success)' }}>{highRating}</div>
            <div className="dash-hero-label">高危评级扫描</div>
          </div>
        </div>
      )}

      {loading && (
        <div className="dashboard-loading">
          <span className="scan-spinner" /><span>加载真实扫描数据…</span>
        </div>
      )}

      {/* ======== 真实扫描结果（可展开卡片）======== */}
      {!loading && realScans.length > 0 && (
        <>
          <div className="dash-chart-title" style={{ marginBottom: 16, fontSize: 15 }}>
            🎯 真实扫描记录（{realScans.length} 次）
            <span style={{ fontSize: 11, color: 'var(--success)', fontWeight: 400, marginLeft: 8 }}>
              ● 数据库实时数据
            </span>
          </div>

          {realScans.map((scan, i) => {
            const data = scan?.data || scan;
            const stats = scan?.stats || {};
            const sa = data?.security_assessment || {};
            const ra = data?.result_analysis || {};
            const vulns = extractVulns(scan);
            const leaks = extractLeaks(scan);
            const rating = sa.overall_rating || 'unknown';
            const summary = ra.summary || sa.summary || '';
            const defense = ra.defense_level || 'unknown';
            const targetUrl = scan?.target_url || data?.target_url || '';
            const date = scan.created_at ? new Date(scan.created_at).toLocaleString() : '';
            const phase1Hits = (data?.execution_results || []).filter((r) => {
              const t = (r.response_text || '').toLowerCase();
              return r.status_code >= 200 && r.status_code < 300 && !t.includes('unauthorized') && !t.includes('not found');
            }).length;

            return (
              <div key={i} className="case-card" style={{ borderColor: rating === 'high' ? 'var(--danger)' : 'var(--border)' }}>
                <div className="case-header" onClick={() => setExpandedReal(expandedReal === i ? null : i)}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span style={{ fontSize: 24 }}>{rating === 'high' ? '🔴' : rating === 'medium' ? '🟡' : '🟢'}</span>
                    <div>
                      <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>
                        {targetUrl.length > 60 ? targetUrl.slice(0, 60) + '…' : targetUrl}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                        {date} · {stats.ai_model || scan?.model_used || 'AI'} · 防御水平: {defense.toUpperCase()}
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                    <div style={{ display: 'flex', gap: 12 }}>
                      <div style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: 20, fontWeight: 700, color: vulns.length > 0 ? 'var(--danger)' : 'var(--success)' }}>{vulns.length}</div>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>漏洞</div>
                      </div>
                      <div style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: 20, fontWeight: 700, color: phase1Hits > 0 ? 'var(--warning)' : 'var(--text-muted)' }}>{phase1Hits}</div>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>命中</div>
                      </div>
                      <div style={{ textAlign: 'center' }}>
                        <span className={`rating-badge-sm ${rating}`}>{rating.toUpperCase()}</span>
                      </div>
                    </div>
                    <button
                      className="btn-report-download"
                      title="下载 PDF 报告"
                      onClick={(e) => {
                        e.stopPropagation();
                        window.open(`${API_BASE}/scans/${scan.scan_id}/report?format=pdf`, '_blank');
                      }}
                    >
                      📄 PDF
                    </button>
                    <span className={`card-chevron ${expandedReal === i ? 'open' : ''}`}>▼</span>
                  </div>
                </div>

                {expandedReal === i && (
                  <div className="case-body">
                    {/* Summary */}
                    {summary && (
                      <div className="remediation-box" style={{ marginTop: 0, marginBottom: 16 }}>
                        <strong>AI 分析总结：</strong>{summary}
                      </div>
                    )}

                    {/* 操作按钮 */}
                    <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
                      <button
                        className="btn btn-primary"
                        style={{ fontSize: 12, padding: '6px 14px' }}
                        onClick={() => window.open(`${API_BASE}/scans/${scan.scan_id}/report?format=pdf`, '_blank')}
                      >
                        📄 下载 PDF 安全报告
                      </button>
                      <button
                        className="btn btn-primary"
                        style={{ fontSize: 12, padding: '6px 14px', background: 'var(--accent)' }}
                        onClick={() => window.open(`${API_BASE}/scans/${scan.scan_id}/report?format=json`, '_blank')}
                      >
                        📋 导出 JSON 数据
                      </button>
                    </div>

                    {/* Stats */}
                    <div style={{ display: 'flex', gap: 24, marginBottom: 16, flexWrap: 'wrap' }}>
                      {[
                        ['攻击方案', (stats.phase1_plan_count || 0) + (stats.phase2_plan_count || 0)],
                        ['已执行请求', (stats.phase1_executed || 0) + (stats.phase2_executed || 0)],
                        ['潜在命中', phase1Hits],
                        ['安全评级', rating.toUpperCase()],
                      ].map(([label, val], j) => (
                        <div key={j} style={{ textAlign: 'center' }}>
                          <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>{val}</div>
                          <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{label}</div>
                        </div>
                      ))}
                    </div>

                    {/* 漏洞详情 */}
                    {vulns.length > 0 && (
                      <>
                        <div className="case-findings-title">🔴 发现的漏洞（AI 确认）</div>
                        <div className="case-findings-list">
                          {vulns.map((v, k) => {
                            const vt = v.vulnerability_type || v.vuln_type || 'unknown';
                            const sev = v.severity || 'medium';
                            const find = v.finding || v.description || JSON.stringify(v);
                            const ep = v.endpoint || '';
                            const rec = v.recommendation || '';
                            const cvss = v.cvss_score != null ? `CVSS ${v.cvss_score}` : '';
                            const owasp = v.owasp_category || '';
                            return (
                              <div key={k} className="case-finding-item">
                                <SeverityDot severity={sev} />
                                <div style={{ flex: 1 }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                                    <span className={`card-badge ${sev === 'critical' || sev === 'high' ? 'danger' : sev === 'medium' ? 'warn' : 'success'}`}
                                      style={{ fontSize: 9 }}>{sev.toUpperCase()}</span>
                                    <span style={{ fontWeight: 600, fontSize: 12 }}>{vt.replace(/_/g, ' ').toUpperCase()}</span>
                                    {cvss && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{cvss}</span>}
                                    {owasp && <span style={{ fontSize: 10, color: 'var(--accent)' }}>OWASP {owasp}</span>}
                                  </div>
                                  {ep && <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--accent)', marginBottom: 2 }}>{ep}</div>}
                                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{find}</div>
                                  {rec && <div style={{ fontSize: 11, color: 'var(--success)', marginTop: 3 }}>💡 {rec}</div>}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </>
                    )}

                    {/* 信息泄露 */}
                    {leaks.length > 0 && (
                      <div style={{ marginTop: 12 }}>
                        <div style={{ fontSize: 13, color: 'var(--warning)', fontWeight: 600, marginBottom: 6 }}>📋 信息泄露发现</div>
                        {leaks.map((lk, k) => (
                          <div key={k} style={{ fontSize: 12, color: 'var(--text-secondary)', padding: '4px 0' }}>
                            ▸ {typeof lk === 'string' ? lk : JSON.stringify(lk)}
                          </div>
                        ))}
                      </div>
                    )}

                    {vulns.length === 0 && (
                      <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: 12 }}>
                        该次扫描未确认新漏洞，或 AI 将漏洞以不同结构返回。查看原始 JSON 获取完整数据。
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </>
      )}

      {/* ======== 靶场案例（固定内容）======== */}
      <div className="dash-chart-title" style={{ marginTop: 32, marginBottom: 16, fontSize: 15 }}>
        🛒 靶场漏洞清单（已知漏洞覆盖验证）
      </div>

      <div className="case-card">
        <div className="case-header" onClick={() => setExpandedDemo(expandedDemo === 'demo' ? null : 'demo')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 28 }}>🛒</span>
            <div>
              <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>电商 API 靶场测试</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>NestJS 模拟电商系统 · 12 端点 · 10 种故意注入的漏洞</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{ display: 'flex', gap: 12 }}>
              <div style={{ textAlign: 'center' }}><div style={{ fontSize: 20, fontWeight: 700, color: 'var(--danger)' }}>8</div><div style={{ fontSize: 10, color: 'var(--text-muted)' }}>漏洞</div></div>
              <div style={{ textAlign: 'center' }}><div style={{ fontSize: 20, fontWeight: 700, color: 'var(--danger)' }}>3</div><div style={{ fontSize: 10, color: 'var(--text-muted)' }}>严重</div></div>
              <div style={{ textAlign: 'center' }}><div style={{ fontSize: 20, fontWeight: 700, color: 'var(--accent)' }}>15</div><div style={{ fontSize: 10, color: 'var(--text-muted)' }}>攻击</div></div>
            </div>
            <span className={`card-chevron ${expandedDemo === 'demo' ? 'open' : ''}`}>▼</span>
          </div>
        </div>

        {expandedDemo === 'demo' && (
          <div className="case-body">
            <div className="case-findings-title">🔴 靶场内含漏洞清单</div>
            <div className="case-findings-list">
              {[
                'BOLA/IDOR 越权：可遍历 order_id 篡改任意用户订单地址',
                'Mass Assignment：注册时可注入 role=admin 及 credit=99999',
                '敏感信息泄露：/api/users/all 返回全部用户明文密码和 secret_token',
                '业务逻辑绕过：订单创建不校验 price，可设置负数实现"倒贴钱"',
                '命令注入：/api/utils/ping 直接拼接用户输入到 shell 命令',
                'SSRF：/api/proxy/fetch 可代理请求内网任意地址',
                '暴力破解：登录接口明确区分"用户名不存在"和"密码错误"',
                '开放重定向：/api/redirect 无域名白名单校验',
              ].map((h, i) => (
                <div key={i} className="case-finding-item">
                  <SeverityDot severity={i < 3 ? 'critical' : i < 7 ? 'high' : 'medium'} />
                  <span>{h}</span>
                </div>
              ))}
            </div>
            <div className="case-vuln-grid">
              {[
                { type: 'BOLA/IDOR 越权', severity: 'critical', count: 2 },
                { type: 'Mass Assignment', severity: 'high', count: 1 },
                { type: '信息泄露', severity: 'high', count: 2 },
                { type: '逻辑绕过', severity: 'medium', count: 1 },
                { type: '命令注入', severity: 'critical', count: 1 },
                { type: 'SSRF', severity: 'high', count: 1 },
              ].map((v, i) => (
                <div key={i} className="case-vuln-chip">
                  <SeverityDot severity={v.severity} />
                  <span style={{ fontWeight: 600, fontSize: 12 }}>{v.type}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>×{v.count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Empty state */}
      {!loading && realScans.length === 0 && (
        <div className="empty-state" style={{ padding: '40px 0', marginTop: 24 }}>
          <div className="empty-icon">🔬</div>
          <div className="empty-title">暂无真实扫描记录</div>
          <div className="empty-desc">
            前往「安全扫描」页面，输入靶场 Swagger 地址并启动扫描。完成后真实测试案例将在此展示。
          </div>
        </div>
      )}
    </div>
  );
}
