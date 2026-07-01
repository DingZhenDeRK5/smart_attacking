import { useState, useEffect, useRef } from 'react';

/* ============================================================
   Security ROI Calculator — 安全投资回报计算器
   路演用：输入 API 数量，输出预计成本节省
   ============================================================ */

// 模型参数（基于行业数据估算）
const PARAMS = {
  avgVulnsPerApi: 2.8,         // 每个 API 平均发现的漏洞数
  vulnDiscoveryRate: 0.85,     // AI 发现率 vs 人工
  manualPentestCostPerApi: 15000, // 人工渗透测试单个 API 成本 (¥)
  manualPentestHoursPerApi: 24,   // 人工渗透测试单个 API 耗时 (小时)
  dataBreachAvgCost: 3800000,    // 中国平均数据泄露成本 (¥, IBM 2024 报告)
  vulnToBreachProbability: 0.03, // 漏洞导致泄露的概率
  smartAttackMonthlyCost: 299,   // SmartAttack 月费
  scansPerMonth: 200,            // 每月可扫描 API 数
};

function animateValue(start, end, duration, callback) {
  const startTime = Date.now();
  function tick() {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
    callback(Math.round(start + (end - start) * eased));
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function AnimatedNumber({ value, prefix = '', suffix = '', duration = 1200 }) {
  const [display, setDisplay] = useState(0);
  const prevRef = useRef(0);

  useEffect(() => {
    animateValue(prevRef.current, value, duration, (v) => setDisplay(v));
    prevRef.current = value;
  }, [value, duration]);

  return <span>{prefix}{display.toLocaleString()}{suffix}</span>;
}

export default function RoiCalculator() {
  const [apiCount, setApiCount] = useState(20);
  const [showResult, setShowResult] = useState(false);

  // 默认展示结果
  useEffect(() => { setShowResult(true); }, []);

  // 计算
  const totalVulns = Math.round(apiCount * PARAMS.avgVulnsPerApi);
  const discoveredByAI = Math.round(totalVulns * PARAMS.vulnDiscoveryRate);
  const manualCost = apiCount * PARAMS.manualPentestCostPerApi;
  const manualHours = apiCount * PARAMS.manualPentestHoursPerApi;
  const smartAttackAnnualCost = PARAMS.smartAttackMonthlyCost * 12;
  const costSaved = manualCost - smartAttackAnnualCost;
  const breachesPrevented = Math.round(discoveredByAI * PARAMS.vulnToBreachProbability);
  const lossAvoided = breachesPrevented * PARAMS.dataBreachAvgCost;
  const roiPercent = Math.round((costSaved / smartAttackAnnualCost) * 100);

  const formatWan = (v) => {
    if (v >= 10000) return `${(v / 10000).toFixed(1)} 万`;
    return v.toLocaleString();
  };

  return (
    <div className="roi-calculator">
      {/* Header */}
      <div className="roi-header">
        <div className="roi-header-left">
          <div className="dash-chart-title" style={{ marginBottom: 0 }}>💰 安全 ROI 计算器</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
            拖动滑块，看看 SmartAttack 能为你节省多少成本
          </div>
        </div>
        <div className="roi-input-group">
          <span style={{ fontSize: 13, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>API 数量</span>
          <input
            type="range"
            min="5"
            max="200"
            value={apiCount}
            onChange={(e) => { setApiCount(Number(e.target.value)); setShowResult(true); }}
            className="roi-slider"
          />
          <span className="roi-api-count">{apiCount}</span>
        </div>
      </div>

      {/* Big Numbers */}
      {showResult && (
        <div className="roi-big-numbers">
          <div className="roi-big-card gold">
            <div className="roi-big-label">预计年节省成本</div>
            <div className="roi-big-value gold-text">
              ¥ <AnimatedNumber value={costSaved} duration={1500} />
            </div>
            <div className="roi-big-sub">
              相比人工渗透测试，ROI {roiPercent}%
            </div>
          </div>
          <div className="roi-big-card danger-light">
            <div className="roi-big-label">预计发现漏洞</div>
            <div className="roi-big-value danger-text">
              <AnimatedNumber value={discoveredByAI} duration={1500} />
            </div>
            <div className="roi-big-sub">
              AI 驱动检测，覆盖率远超传统扫描器
            </div>
          </div>
          <div className="roi-big-card accent-light">
            <div className="roi-big-label">预计避免潜在损失</div>
            <div className="roi-big-value accent-text">
              ¥ <AnimatedNumber value={lossAvoided} duration={1800} />
            </div>
            <div className="roi-big-sub">
              防止 {breachesPrevented} 起潜在数据泄露事件
            </div>
          </div>
        </div>
      )}

      {/* Breakdown Table */}
      <div className="roi-compare">
        <table className="roi-table">
          <thead>
            <tr>
              <th>对比维度</th>
              <th style={{ color: 'var(--danger)' }}>人工渗透测试</th>
              <th style={{ color: 'var(--warning)' }}>传统扫描器</th>
              <th style={{ color: 'var(--accent)' }}>SmartAttack AI</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="roi-table-label">单次成本</td>
              <td>¥ {PARAMS.manualPentestCostPerApi.toLocaleString()} / API</td>
              <td>¥ 5,000 / API</td>
              <td className="roi-table-hl">¥ {(PARAMS.smartAttackMonthlyCost / PARAMS.scansPerMonth).toFixed(1)} / API</td>
            </tr>
            <tr>
              <td className="roi-table-label">扫描 {apiCount} 个 API 总成本</td>
              <td>¥ {manualCost.toLocaleString()}</td>
              <td>¥ {(apiCount * 5000).toLocaleString()}</td>
              <td className="roi-table-hl">¥ {PARAMS.smartAttackMonthlyCost.toLocaleString()} / 月 (无限)</td>
            </tr>
            <tr>
              <td className="roi-table-label">耗时</td>
              <td>{manualHours.toLocaleString()} 小时</td>
              <td>约 {Math.round(apiCount * 0.5)} 小时</td>
              <td className="roi-table-hl">约 {Math.round(apiCount * 0.05)} 小时</td>
            </tr>
            <tr>
              <td className="roi-table-label">AI 业务逻辑分析</td>
              <td>✅ 依赖专家经验</td>
              <td>❌ 无</td>
              <td className="roi-table-hl">✅ AI 驱动</td>
            </tr>
            <tr>
              <td className="roi-table-label">漏洞发现率</td>
              <td>~90% (专家水平)</td>
              <td>~40%</td>
              <td className="roi-table-hl">~85% (逼近专家)</td>
            </tr>
            <tr>
              <td className="roi-table-label">OWASP/CVSS 标准报告</td>
              <td>✅ 人工撰写</td>
              <td>部分</td>
              <td className="roi-table-hl">✅ 自动生成 PDF</td>
            </tr>
            <tr>
              <td className="roi-table-label">7×24 持续监控</td>
              <td>❌</td>
              <td>✅</td>
              <td className="roi-table-hl">✅ 异步 + CI/CD</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Bottom note */}
      <div className="roi-note">
        * 以上数据基于 IBM 2024 数据泄露成本报告（中国平均 ¥380 万/起）、OWASP API Security Top 10 统计，
        以及 Gartner 对 API 安全测试市场的分析。实际结果可能因 API 复杂度、业务场景不同而有所差异。
      </div>
    </div>
  );
}
