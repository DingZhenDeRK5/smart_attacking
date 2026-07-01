import { useState, useEffect } from 'react';
import { API_BASE } from './helpers';
import RoiCalculator from './RoiCalculator';

/* ============================================================
   Dashboard — 安全运营数据看板
   路演展示用：累计统计 / 漏洞分布 / 最近活动
   ============================================================ */

export default function Dashboard({ onNavigate }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // 拉取所有扫描记录来聚合统计数据
    fetch(`${API_BASE}/scans?limit=200`)
      .then((r) => r.json())
      .then((d) => {
        if (d.success) {
          const scans = d.scans || [];
          // 并发拉取详情以获得漏洞数据
          Promise.all(
            scans.slice(0, 20).map((s) =>
              fetch(`${API_BASE}/scans/${s.scan_id}`)
                .then((r) => r.json())
                .then((d) => (d.success ? d.scan : null))
                .catch(() => null)
            )
          ).then((details) => {
            setStats(aggregateStats(scans, details.filter(Boolean)));
            setLoading(false);
          });
        } else {
          setLoading(false);
        }
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="dashboard-loading">
        <span className="scan-spinner" />
        <span>加载安全运营数据…</span>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="empty-state">
        <div className="empty-icon">📊</div>
        <div className="empty-title">暂无数据</div>
        <div className="empty-desc">完成一次 AI 渗透扫描后，仪表盘将自动聚合安全数据。</div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      {/* ======== Hero Stats ======== */}
      <div className="dash-hero-row">
        <div className="dash-hero-card">
          <div className="dash-hero-icon" style={{ background: 'var(--accent-soft)' }}>⚡</div>
          <div className="dash-hero-body">
            <div className="dash-hero-value">{stats.totalScans}</div>
            <div className="dash-hero-label">累计扫描次数</div>
          </div>
          <div className="dash-hero-trend up">↑ {stats.scansThisMonth} 本月</div>
        </div>
        <div className="dash-hero-card">
          <div className="dash-hero-icon" style={{ background: 'var(--danger-soft)' }}>🐛</div>
          <div className="dash-hero-body">
            <div className="dash-hero-value" style={{ color: 'var(--danger)' }}>{stats.totalVulns}</div>
            <div className="dash-hero-label">发现漏洞总数</div>
          </div>
          <div className="dash-hero-trend up" style={{ color: 'var(--danger)' }}>
            {stats.criticalCount} 严重
          </div>
        </div>
        <div className="dash-hero-card">
          <div className="dash-hero-icon" style={{ background: 'var(--warning-soft)' }}>🎯</div>
          <div className="dash-hero-body">
            <div className="dash-hero-value" style={{ color: 'var(--warning)' }}>{stats.avgRiskScore}</div>
            <div className="dash-hero-label">平均 CVSS 风险分</div>
          </div>
          <div className="dash-hero-trend" style={{ color: 'var(--text-muted)' }}>满分 10.0</div>
        </div>
        <div className="dash-hero-card">
          <div className="dash-hero-icon" style={{ background: 'var(--success-soft)' }}>✅</div>
          <div className="dash-hero-body">
            <div className="dash-hero-value" style={{ color: 'var(--success)' }}>{stats.successRate}%</div>
            <div className="dash-hero-label">扫描成功率</div>
          </div>
          <div className="dash-hero-trend" style={{ color: 'var(--success)' }}>
            {stats.completedScans}/{stats.totalScans} 完成
          </div>
        </div>
      </div>

      {/* ======== Charts Row ======== */}
      <div className="dash-charts-row">
        {/* 漏洞严重度分布 */}
        <div className="dash-chart-card">
          <div className="dash-chart-title">漏洞严重度分布</div>
          <div className="severity-bars">
            {[
              { label: '严重', key: 'critical', color: '#8B0000', count: stats.severityBreakdown.critical },
              { label: '高危', key: 'high', color: 'var(--danger)', count: stats.severityBreakdown.high },
              { label: '中危', key: 'medium', color: 'var(--warning)', count: stats.severityBreakdown.medium },
              { label: '低危', key: 'low', color: 'var(--success)', count: stats.severityBreakdown.low },
              { label: '信息', key: 'info', color: 'var(--info)', count: stats.severityBreakdown.info },
            ].map((s) => (
              <div key={s.key} className="severity-bar-row">
                <span className="severity-bar-label">{s.label}</span>
                <div className="severity-bar-track">
                  <div
                    className="severity-bar-fill"
                    style={{
                      width: `${stats.totalVulns > 0 ? (s.count / stats.totalVulns) * 100 : 0}%`,
                      background: s.color,
                    }}
                  />
                </div>
                <span className="severity-bar-count">{s.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* 漏洞类型 TOP 5 */}
        <div className="dash-chart-card">
          <div className="dash-chart-title">漏洞类型 TOP 5</div>
          <div className="severity-bars">
            {stats.topTypes.slice(0, 5).map((t, i) => (
              <div key={i} className="severity-bar-row">
                <span className="severity-bar-label" style={{ textTransform: 'capitalize' }}>
                  {t.type.replace(/_/g, ' ')}
                </span>
                <div className="severity-bar-track">
                  <div
                    className="severity-bar-fill"
                    style={{
                      width: `${stats.totalVulns > 0 ? (t.count / stats.totalVulns) * 100 : 0}%`,
                      background: ['var(--danger)', 'var(--warning)', 'var(--accent)', 'var(--info)', 'var(--success)'][i],
                    }}
                  />
                </div>
                <span className="severity-bar-count">{t.count}</span>
              </div>
            ))}
            {stats.topTypes.length === 0 && (
              <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: 12 }}>暂无漏洞数据</div>
            )}
          </div>
        </div>
      </div>

      {/* ======== Recent Activity & Quick Start ======== */}
      <div className="dash-charts-row">
        {/* 最近扫描活动 */}
        <div className="dash-chart-card" style={{ flex: 2 }}>
          <div className="dash-chart-title">最近扫描活动</div>
          <div className="activity-feed">
            {stats.recentScans.length === 0 && (
              <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: 12 }}>暂无扫描记录</div>
            )}
            {stats.recentScans.map((scan, i) => (
              <div key={i} className="activity-item">
                <div className={`activity-dot ${scan.rating || 'unknown'}`} />
                <div className="activity-body">
                  <div className="activity-url" title={scan.url}>{scan.url}</div>
                  <div className="activity-meta">
                    <span>{scan.date}</span>
                    <span>·</span>
                    <span>{scan.plans} 组攻击方案</span>
                    <span>·</span>
                    <span>{scan.executed} 次请求</span>
                    <span>·</span>
                    <span className={`rating-badge-sm ${scan.rating || 'unknown'}`}>
                      {scan.rating?.toUpperCase() || '?'}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 快速操作 */}
        <div className="dash-chart-card" style={{ flex: 1 }}>
          <div className="dash-chart-title">快速操作</div>
          <div className="quick-actions">
            <button className="btn btn-primary" onClick={() => onNavigate?.('scanner')}>
              🚀 新建扫描
            </button>
            <button className="btn btn-primary" style={{ background: 'var(--success)' }}
              onClick={() => onNavigate?.('scanner')}>
              📄 查看最新报告
            </button>
            <button className="btn btn-primary" style={{ background: 'var(--warning)' }}
              onClick={() => onNavigate?.('scanner')}>
              🔍 对比两次扫描
            </button>
            <button className="btn btn-primary" style={{ background: '#8b5cf6' }}
              onClick={() => onNavigate?.('pricing')}>
              💎 升级专业版
            </button>
          </div>

          <div className="dash-chart-title" style={{ marginTop: 20 }}>平台能力</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
            {[
              'AI 驱动的业务逻辑安全分析',
              'OWASP Top 10 + CVSS 3.1 评级',
              '一键 PDF 专业安全报告',
              '异步扫描 + 历史对比',
              '多模型适配 (DeepSeek/OpenAI/Claude)',
            ].map((s, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)' }}>
                <span style={{ color: 'var(--success)' }}>✓</span> {s}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ======== ROI Calculator ======== */}
      <RoiCalculator />
    </div>
  );
}

/* ============================================================
   数据聚合逻辑
   ============================================================ */
function aggregateStats(summaries, details) {
  const totalScans = summaries.length;
  const completedScans = summaries.filter((s) => s.status === 'completed' || !s.status).length;
  const failedScans = summaries.filter((s) => s.status === 'failed').length;

  // 汇总所有漏洞
  const allVulns = [];
  const vulnTypeCount = {};
  const severityCount = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  details.forEach((scan) => {
    const data = scan?.data || scan;
    const assessment = data?.security_assessment || {};
    const vulns = assessment.vulnerabilities_found || [];
    vulns.forEach((v) => {
      allVulns.push(v);
      const t = v.vulnerability_type || v.vuln_type || 'unknown';
      vulnTypeCount[t] = (vulnTypeCount[t] || 0) + 1;
      const sev = v.severity || 'medium';
      if (severityCount[sev] !== undefined) severityCount[sev]++;
    });
  });

  // CVSS 平均分
  const scores = allVulns.map((v) => v.cvss_score || 0).filter((s) => s > 0);
  const avgRiskScore = scores.length > 0 ? (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1) : '—';

  // TOP 5 漏洞类型
  const topTypes = Object.entries(vulnTypeCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([type, count]) => ({ type, count }));

  // 本月扫描数
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const scansThisMonth = summaries.filter((s) => s.created_at && new Date(s.created_at) >= monthStart).length;

  // 最近 8 条扫描
  const recentScans = summaries.slice(0, 8).map((s) => ({
    url: s.target_url || 'unknown',
    date: s.created_at ? new Date(s.created_at).toLocaleDateString() : '',
    plans: s.stats?.phase1_plan_count || 0,
    executed: s.stats?.phase1_executed || 0,
    rating: s.overall_rating || 'unknown',
  }));

  return {
    totalScans,
    completedScans,
    failedScans,
    totalVulns: allVulns.length,
    criticalCount: severityCount.critical + severityCount.high,
    avgRiskScore,
    successRate: totalScans > 0 ? Math.round((completedScans / totalScans) * 100) : 100,
    scansThisMonth,
    severityBreakdown: severityCount,
    topTypes,
    recentScans,
  };
}
