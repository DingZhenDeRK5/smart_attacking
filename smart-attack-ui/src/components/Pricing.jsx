import './helpers';

/* ============================================================
   Pricing — 三档定价 + 功能对比
   路演展示用：Freemium 商业模式
   ============================================================ */

const PLANS = [
  {
    name: '免费版',
    nameEn: 'Starter',
    price: '0',
    period: '永久免费',
    color: 'var(--accent)',
    bgSoft: 'var(--accent-soft)',
    description: '适合个人开发者体验 AI 安全扫描',
    features: [
      { text: '每月 5 次 AI 扫描', included: true },
      { text: '基础漏洞检测 (BOLA/注入/信息泄露)', included: true },
      { text: '在线结果查看', included: true },
      { text: '单次扫描报告 (JSON)', included: true },
      { text: '扫描历史 (最近 10 条)', included: true },
      { text: 'PDF 专业报告导出', included: false },
      { text: '异步后台扫描', included: false },
      { text: '扫描对比 & 差分分析', included: false },
      { text: '认证感知扫描 (JWT/API Key)', included: false },
      { text: '多模型切换 (OpenAI/Claude)', included: false },
      { text: 'CI/CD 集成 (GitHub Action)', included: false },
      { text: '团队协作 & 项目空间', included: false },
      { text: '优先技术支持', included: false },
    ],
    cta: '免费开始',
    highlighted: false,
  },
  {
    name: '专业版',
    nameEn: 'Professional',
    price: '299',
    period: '/月',
    color: '#8b5cf6',
    bgSoft: 'rgba(139, 92, 246, 0.12)',
    description: '适合安全团队 & 中小企业持续安全监控',
    features: [
      { text: '无限次 AI 扫描', included: true, highlight: true },
      { text: '全类型漏洞检测', included: true },
      { text: '在线结果查看 + 实时通知', included: true },
      { text: 'PDF 专业安全报告 (含 OWASP/CVSS)', included: true, highlight: true },
      { text: '无限扫描历史 & 搜索', included: true },
      { text: '异步后台扫描 + 进度追踪', included: true, highlight: true },
      { text: '扫描对比 & 差分分析', included: true, highlight: true },
      { text: '认证感知扫描 (JWT/API Key)', included: true },
      { text: '多模型切换 (DeepSeek/OpenAI/Claude)', included: true },
      { text: 'CI/CD 集成 (GitHub Action)', included: false },
      { text: '团队协作 & 项目空间', included: false },
      { text: '邮件技术支持 (48h)', included: true },
    ],
    cta: '立即订阅',
    highlighted: true,
    badge: '最受欢迎',
  },
  {
    name: '企业版',
    nameEn: 'Enterprise',
    price: '999',
    period: '/月',
    color: 'var(--warning)',
    bgSoft: 'var(--warning-soft)',
    description: '适合大型企业 & 合规审计需求',
    features: [
      { text: '无限次 AI 扫描', included: true },
      { text: '全类型漏洞检测 + 自定义规则', included: true, highlight: true },
      { text: '在线结果查看 + 实时告警', included: true },
      { text: 'PDF 专业安全报告 (含合规映射)', included: true },
      { text: '无限扫描历史 & 高级搜索', included: true },
      { text: '异步后台扫描 + 批量任务', included: true },
      { text: '扫描对比 & 差分分析', included: true },
      { text: '认证感知扫描 (JWT/OAuth2/API Key)', included: true },
      { text: '全部模型支持 (含私有部署)', included: true, highlight: true },
      { text: 'CI/CD 集成 (GitHub/GitLab/Jenkins)', included: true, highlight: true },
      { text: '团队协作 & 项目空间 (不限成员)', included: true, highlight: true },
      { text: '专属技术支持 (1h 响应)', included: true, highlight: true },
      { text: '等保 / GDPR / PCI-DSS 合规报告', included: true, highlight: true },
      { text: '私有化部署选项', included: true },
    ],
    cta: '联系销售',
    highlighted: false,
  },
];

export default function Pricing({ onNavigate }) {
  return (
    <div className="pricing-page">
      {/* ======== Hero ======== */}
      <div className="pricing-hero">
        <h1 className="pricing-hero-title">选择最适合你的方案</h1>
        <p className="pricing-hero-sub">
          从免费开始，随业务增长升级。所有方案均包含 AI 驱动的 API 安全分析核心能力。
        </p>
      </div>

      {/* ======== Plan Cards ======== */}
      <div className="pricing-cards">
        {PLANS.map((plan) => (
          <div
            key={plan.nameEn}
            className={`pricing-card ${plan.highlighted ? 'highlighted' : ''}`}
            style={{ borderColor: plan.highlighted ? plan.color : 'var(--border)' }}
          >
            {plan.badge && (
              <div className="pricing-badge" style={{ background: plan.color }}>
                {plan.badge}
              </div>
            )}
            <div className="pricing-card-header">
              <div className="pricing-card-name">{plan.name}</div>
              <div className="pricing-card-name-en">{plan.nameEn}</div>
            </div>
            <div className="pricing-card-price">
              <span className="pricing-currency">¥</span>
              <span className="pricing-amount" style={{ color: plan.color }}>{plan.price}</span>
              <span className="pricing-period">{plan.period}</span>
            </div>
            <p className="pricing-card-desc">{plan.description}</p>

            <button
              className="btn btn-primary"
              style={{
                background: plan.highlighted ? plan.color : 'var(--bg-input)',
                color: plan.highlighted ? '#fff' : 'var(--text-primary)',
                border: plan.highlighted ? 'none' : '1px solid var(--border)',
                width: '100%',
                marginBottom: 20,
              }}
              onClick={() => onNavigate?.('scanner')}
            >
              {plan.cta}
            </button>

            <div className="pricing-features">
              {plan.features.map((f, i) => (
                <div key={i} className={`pricing-feature ${f.highlight ? 'hl' : ''}`}>
                  <span style={{ color: f.included ? 'var(--success)' : 'var(--text-muted)', fontWeight: 700 }}>
                    {f.included ? '✓' : '✕'}
                  </span>
                  <span style={{
                    color: f.included ? 'var(--text-primary)' : 'var(--text-muted)',
                    fontWeight: f.highlight ? 600 : 400,
                    textDecoration: f.included ? 'none' : 'line-through',
                  }}>
                    {f.text}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* ======== Single Scan Pricing ======== */}
      <div className="pricing-scan-section">
        <div className="pricing-scan-header">
          <h2 className="pricing-section-title">单次扫描定价</h2>
          <p className="pricing-scan-sub">
            以上方案仅为平台使用门槛。每次实际执行 AI 安全扫描将根据服务深度按次计费。
            所有扫描均包含 AI 业务分析、攻击载荷生成、结果评估与在线报告。
          </p>
        </div>

        <div className="pricing-scan-cards">
          {[
            {
              tier: '基础',
              name: 'API 扫描报告',
              priceRange: '399 – 799',
              unit: '元/次',
              color: '#6366f1',
              icon: '📋',
              desc: '标准安全漏洞检测，覆盖 OWASP Top 10 常见风险，生成基础评估报告。',
              includes: [
                'Swagger/OpenAPI 文档解析',
                'OWASP Top 10 漏洞扫描 (8 类)',
                'AI 攻击方案生成 (≥15 组)',
                '在线结果查看',
                '基础 JSON 报告',
              ],
            },
            {
              tier: '标准',
              name: 'API 安全扫描',
              priceRange: '1,599 – 2,999',
              unit: '元/次',
              color: '#8b5cf6',
              icon: '🛡️',
              desc: '深度安全扫描 + 影子 API 发现 + 认证感知测试 + PDF 专业报告。',
              includes: [
                '包含「基础」全部内容',
                '影子 API 发现与检测',
                '认证感知扫描 (JWT/API Key)',
                '全 12 类漏洞深度检测',
                'AI 精炼后续攻击 (2 轮)',
                'PDF 专业安全报告 (含 CVSS 评分)',
                '扫描结果数据库留存',
              ],
              highlighted: true,
              badge: '推荐',
            },
            {
              tier: '高级',
              name: 'API 风险分析',
              priceRange: '3,999 – 7,999',
              unit: '元/次',
              color: '#f59e0b',
              icon: '🔬',
              desc: '全面风险分析 + 合规映射 + 修复方案 + 安全加固建议，适合等保/合规场景。',
              includes: [
                '包含「标准」全部内容',
                '全量 API 端点枚举与遍历',
                '业务逻辑深度审计',
                '合规映射 (等保/GDPR/PCI-DSS)',
                '漏洞修复方案与代码建议',
                '安全加固专项报告',
                '人工复核 + 专家解读 (可选)',
              ],
            },
          ].map((scan, i) => (
            <div
              key={scan.tier}
              className={`pricing-scan-card ${scan.highlighted ? 'highlighted' : ''}`}
              style={{ borderColor: scan.highlighted ? scan.color : 'var(--border)' }}
            >
              {scan.badge && (
                <div className="pricing-badge" style={{ background: scan.color }}>
                  {scan.badge}
                </div>
              )}
              <div className="pricing-scan-card-top">
                <span className="pricing-scan-icon">{scan.icon}</span>
                <div>
                  <div className="pricing-scan-tier">{scan.tier}</div>
                  <div className="pricing-scan-name">{scan.name}</div>
                </div>
              </div>
              <div className="pricing-card-price" style={{ marginTop: 12 }}>
                <span className="pricing-currency">¥</span>
                <span className="pricing-amount" style={{ color: scan.color, fontSize: 32 }}>
                  {scan.priceRange}
                </span>
                <span className="pricing-period">{scan.unit}</span>
              </div>
              <p className="pricing-card-desc">{scan.desc}</p>
              <div className="pricing-features">
                {scan.includes.map((f, j) => (
                  <div key={j} className="pricing-feature">
                    <span style={{ color: 'var(--success)', fontWeight: 700 }}>✓</span>
                    <span style={{ color: 'var(--text-primary)' }}>{f}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Pricing note */}
        <div className="pricing-scan-note">
          <span style={{ marginRight: 6 }}>💡</span>
          以上为参考价格区间，实际费用根据 API 端点数量、认证复杂度、扫描深度浮动。
          企业版用户享 8 折优惠，年度框架协议可另行协商。
        </div>
      </div>

      {/* ======== Feature Comparison Table ======== */}
      <div className="pricing-compare-section">
        <h2 className="pricing-section-title">功能详细对比</h2>
        <div className="pricing-compare-table">
          <table>
            <thead>
              <tr>
                <th>功能</th>
                <th>免费版</th>
                <th className="hl-col">专业版</th>
                <th>企业版</th>
              </tr>
            </thead>
            <tbody>
              {[
                ['AI 扫描次数', '5 次/月', '无限', '无限'],
                ['漏洞检测类型', '5 种', '全部 12 种', '全部 12 种 + 自定义'],
                ['PDF 报告', '—', '✅ 含 OWASP/CVSS', '✅ 含合规映射'],
                ['异步扫描', '—', '✅', '✅ 批量任务'],
                ['扫描对比', '—', '✅', '✅'],
                ['认证扫描', '—', '✅ JWT/API Key', '✅ JWT/OAuth2/API Key'],
                ['AI 模型', 'DeepSeek', 'DeepSeek/OpenAI/Claude', '全部 + 私有部署'],
                ['CI/CD 集成', '—', '—', '✅ GitHub/GitLab/Jenkins'],
                ['团队协作', '—', '—', '✅ 不限成员'],
                ['合规报告', '—', '—', '✅ 等保/GDPR/PCI-DSS'],
                ['技术支持', '社区论坛', '邮件 48h', '专属 1h 响应'],
                ['私有化部署', '—', '—', '✅'],
              ].map((row, i) => (
                <tr key={i}>
                  <td className="feature-name">{row[0]}</td>
                  <td>{row[1]}</td>
                  <td className="hl-col">{row[2]}</td>
                  <td>{row[3]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ======== Bottom CTA ======== */}
      <div className="pricing-cta-bottom">
        <h2>准备好保护你的 API 了吗？</h2>
        <p>预计帮助企业在首年发现 50+ 未登记的影子 API，避免潜在数据泄露损失</p>
        <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
          <button className="btn btn-primary" style={{ background: '#8b5cf6', padding: '14px 32px', fontSize: 16 }}
            onClick={() => onNavigate?.('scanner')}>
            🚀 免费开始扫描
          </button>
          <button className="btn btn-primary" style={{
            background: 'var(--bg-input)', color: 'var(--text-primary)',
            border: '1px solid var(--border)', padding: '14px 32px', fontSize: 16,
          }}>
            💬 预约演示
          </button>
        </div>
      </div>
    </div>
  );
}
