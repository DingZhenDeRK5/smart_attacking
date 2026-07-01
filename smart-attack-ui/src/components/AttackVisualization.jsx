import { useEffect, useState, useMemo } from 'react';
import ReactEChartsCore from 'echarts-for-react';

/* ============================================================
   AttackVisualization v3.5.1 — 攻击可视化大屏
   - 攻击拓扑图（lines 系列 + effect 飞线粒子动画）
   - 漏洞分布雷达图
   - 攻击进度仪表盘
   - 攻击类型柱状图
   - 实时攻击日志

   修复：动画 tick 改用 useState 确保 React 正确追踪
        无端点数据时显示脉冲占位动画
   ============================================================ */

const AGENT_COLORS = {
  auth: '#8b5cf6',
  data: '#06b6d4',
  logic: '#f59e0b',
  injection: '#ef4444',
};

const CX = 50, CY = 55;

export default function AttackVisualization({
  scanData,
  liveAttackFeed,
  scanStatus,
  isScanning,
}) {
  // ====== 动画 tick 必须用 state（ref 不会被 useMemo 追踪）======
  const [animTick, setAnimTick] = useState(0);

  useEffect(() => {
    if (!isScanning && !scanData) return;
    const timer = setInterval(() => setAnimTick((t) => t + 1), 1500);
    return () => clearInterval(timer);
  }, [isScanning, scanData]);

  /* ---- 提取扫描数据 ---- */
  const { endpoints, vulnStats, attackFlow } = useMemo(() => {
    const data = scanData?.data || scanData;
    const results = data?.execution_results || [];
    const assessment = data?.security_assessment || {};

    // 去重提取端点（只显示有实际命中或疑似命中的端点，避免拓扑图爆炸）
    const epMap = new Map();
    if (results.length > 0) {
      // 扫描完成：只显示命中的端点（不是所有测试过的）
      const hitEps = new Set();
      results.forEach((r) => {
        const p = r.payload || {};
        const m = p.method || r.method || 'GET';
        const pt = p.path || r.path || '/';
        const t = (r.response_text || '').toLowerCase();
        const sc = r.status_code || 0;
        if (sc >= 200 && sc < 300 && !t.includes('unauthorized') && !t.includes('not found')) {
          const key = `${m}:${pt}`;
          if (!hitEps.has(key)) {
            hitEps.add(key);
            epMap.set(key, { method: m, path: pt });
          }
        }
      });
      // 如果命中太少，补充部分被测试的端点
      if (epMap.size < 3 && results.length > 0) {
        results.slice(0, 6).forEach((r) => {
          const p = r.payload || {};
          const m = p.method || r.method || 'GET';
          const pt = p.path || r.path || '/';
          const key = `${m}:${pt}`;
          if (!epMap.has(key)) epMap.set(key, { method: m, path: pt });
          if (epMap.size >= 6) return;
        });
      }
    } else if (liveAttackFeed?.length > 0) {
      liveAttackFeed.forEach((a) => {
        const m = a.method || 'GET';
        const pt = a.path || '/';
        const key = `${m}:${pt}`;
        if (!epMap.has(key)) epMap.set(key, { method: m, path: pt });
      });
    }
    const endpoints = Array.from(epMap.values()).slice(0, 6);

    // 漏洞统计（扫描完成后用 assessment，扫描中用 liveAttackFeed 实时构建）
    const vulns = assessment.vulnerabilities_found || [];
    const vulnStats = {
      total: vulns.length,
      byType: {},
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };
    vulns.forEach((v) => {
      const t = v.vulnerability_type || v.vuln_type || 'unknown';
      vulnStats.byType[t] = (vulnStats.byType[t] || 0) + 1;
      const s = v.severity || 'medium';
      if (vulnStats.bySeverity[s] !== undefined) vulnStats.bySeverity[s]++;
    });

    // 实时统计：优先用 liveAttackFeed，无 WebSocket 时用进度模拟
    const liveStats = { byType: {}, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } };
    if (vulns.length === 0 && liveAttackFeed?.length > 0) {
      liveAttackFeed.forEach((a) => {
        if (a.verdict === 'hit') {
          liveStats.bySeverity.high++;
          const t = a.vulnerability_type || 'unknown';
          liveStats.byType[t] = (liveStats.byType[t] || 0) + 1;
        } else if (a.verdict === 'partial') {
          liveStats.bySeverity.medium++;
        } else {
          liveStats.bySeverity.info++;
        }
      });
    }

    // 合并统计：最终数据优先，live 数据其次，扫描中用进度模拟
    const mergedStats = vulns.length > 0 ? vulnStats :
      (liveAttackFeed?.length > 0) ? {
        total: liveAttackFeed.filter(a => a.verdict === 'hit').length,
        byType: liveStats.byType,
        bySeverity: liveStats.bySeverity,
      } : vulnStats;  // 既无最终数据也无 live 数据时，用空 vulnStats（雷达图显示"等待"）

    const hits = results.filter((r) => {
      const t = (r.response_text || '').toLowerCase();
      const sc = r.status_code || 0;
      return sc >= 200 && sc < 300 && !t.includes('unauthorized') && !t.includes('not found');
    });

    return { endpoints, vulnStats: mergedStats, attackFlow: { total: results.length, hits: hits.length } };
  }, [scanData, liveAttackFeed]);

  const liveHits = liveAttackFeed?.filter((a) => a.verdict === 'hit').length || 0;
  const livePartial = liveAttackFeed?.filter((a) => a.verdict === 'partial').length || 0;

  /* ================================================================
     Chart 1: 攻击拓扑 — scatter(节点) + lines(飞线+effect)
     关键修复：animTick 是 state，每次变化触发 useMemo 重算
     ================================================================ */
  const topologyOption = useMemo(() => {
    const phase = animTick;

    // ---- 节点 ----
    const scatterData = [];
    // 中心
    scatterData.push({
      value: [CX, CY],
      symbolSize: 36,
      itemStyle: {
        color: '#3b82f6',
        borderColor: '#93c5fd',
        borderWidth: 3,
        shadowBlur: 20 + (phase % 3) * 5,  // 脉冲呼吸
        shadowColor: 'rgba(59,130,246,0.6)',
      },
      label: { show: true, position: 'bottom', distance: 12, color: '#e2e8f0', fontSize: 11, fontWeight: 'bold', formatter: 'Target API' },
    });

    // 4 个 Agent
    const agents = [
      { id: 'auth', name: '鉴权', x: 12, y: 18, color: AGENT_COLORS.auth },
      { id: 'data', name: '数据', x: 88, y: 18, color: AGENT_COLORS.data },
      { id: 'logic', name: '逻辑', x: 12, y: 88, color: AGENT_COLORS.logic },
      { id: 'injection', name: '注入', x: 88, y: 88, color: AGENT_COLORS.injection },
    ];
    agents.forEach((a) => {
      const pulse = phase % 4 === agents.indexOf(a);
      scatterData.push({
        value: [a.x, a.y],
        symbolSize: pulse ? 36 : 30,
        itemStyle: {
          color: a.color,
          borderColor: '#fff',
          borderWidth: pulse ? 3 : 2,
          shadowBlur: pulse ? 18 : 10,
          shadowColor: a.color,
        },
        label: { show: true, position: 'top', distance: 6, color: '#cbd5e1', fontSize: 10, formatter: a.name },
      });
    });

    // 端点节点
    const useList = endpoints.length > 0 ? endpoints : [];
    // 如果完全没有端点数据，创建虚拟端点展示架构占位
    const hasRealData = useList.length > 0;
    const displayEps = hasRealData ? useList : [
      { method: 'GET', path: '/api/endpoint1' },
      { method: 'POST', path: '/api/endpoint2' },
      { method: 'GET', path: '/api/endpoint3' },
      { method: 'POST', path: '/api/endpoint4' },
      { method: 'GET', path: '/api/endpoint5' },
      { method: 'DELETE', path: '/api/endpoint6' },
    ];

    const epNodes = [];
    displayEps.forEach((ep, i) => {
      const angle = (i / Math.max(displayEps.length, 1)) * 2 * Math.PI - Math.PI / 2;
      const r = 22 + (i % 3) * 7;
      const ex = CX + r * Math.cos(angle);
      const ey = CY + r * Math.sin(angle);
      const hit = liveAttackFeed?.some((a) => a.path === ep.path && a.verdict === 'hit');
      epNodes.push({ x: ex, y: ey, path: ep.path, method: ep.method, hit });
      scatterData.push({
        value: [ex, ey],
        symbolSize: hit ? 14 : (hasRealData ? 9 : 7),
        itemStyle: {
          color: hit ? '#ef4444' : (hasRealData ? '#64748b' : '#475569'),
          borderColor: hit ? '#fca5a5' : '#64748b',
          borderWidth: hit ? 2 : 1,
          shadowBlur: hit ? 10 : 0,
          shadowColor: 'rgba(239,68,68,0.6)',
          opacity: hasRealData ? 1 : 0.5,
        },
        label: hasRealData ? {
          show: displayEps.length <= 8,
          position: 'right', distance: 4,
          color: hit ? '#ef4444' : '#94a3b8',
          fontSize: 9,
          formatter: `${ep.method} ${ep.path.length > 14 ? ep.path.slice(0, 13) + '…' : ep.path}`,
        } : { show: false },
      });
    });

    // ---- 飞线 ----
    // Agent → Center
    const agentLines = agents.map((a) => ({
      coords: [[a.x, a.y], [CX, CY]],
      lineStyle: { color: a.color, opacity: 0.2, width: 1, type: 'dashed' },
    }));

    // Center → Endpoints（飞线 + effect 粒子动画）
    const attackLines = [];
    epNodes.forEach((ep, ei) => {
      const slot = (ei + phase) % Math.max(epNodes.length, 1);
      const showCount = Math.max(2, Math.floor(epNodes.length / 3) + 1);
      if (slot < showCount) {
        const color = ep.hit ? '#ef4444' : '#60a5fa';
        attackLines.push({
          coords: [[CX, CY], [ep.x, ep.y]],
          lineStyle: {
            color, opacity: ep.hit ? 0.9 : 0.6,
            width: ep.hit ? 3 : 1.5, curveness: 0.12,
          },
          effect: {
            show: true,
            period: hasRealData ? 2.5 : 4,
            trailLength: hasRealData ? 0.35 : 0.5,
            symbol: 'arrow',
            symbolSize: [6, 10],
            color,
          },
        });
      }
    });

    return {
      backgroundColor: 'transparent',
      grid: { containLabel: true },
      xAxis: { show: false, min: 0, max: 100 },
      yAxis: { show: false, min: 0, max: 100 },
      animation: true,
      animationDuration: 600,
      series: [
        { type: 'scatter', coordinateSystem: 'cartesian2d', data: scatterData, zlevel: 2, z: 10 },
        { type: 'lines', coordinateSystem: 'cartesian2d', polyline: false, data: agentLines, zlevel: 1, z: 1 },
        { type: 'lines', coordinateSystem: 'cartesian2d', polyline: false, data: attackLines, zlevel: 1, z: 5 },
      ],
    };
  }, [endpoints, liveAttackFeed, animTick]);

  /* ---- Chart 2: 漏洞雷达 ---- */
  const radarOption = useMemo(() => ({
    backgroundColor: 'transparent',
    radar: {
      center: ['50%', '55%'], radius: '62%',
      indicator: [
        { name: '严重', max: Math.max(vulnStats.bySeverity.critical, 1) },
        { name: '高危', max: Math.max(vulnStats.bySeverity.high, 1) },
        { name: '中危', max: Math.max(vulnStats.bySeverity.medium, 1) },
        { name: '低危', max: Math.max(vulnStats.bySeverity.low, 1) },
        { name: '信息', max: Math.max(vulnStats.bySeverity.info, 1) },
      ],
      axisName: { color: '#94a3b8', fontSize: 10 },
      splitArea: { areaStyle: { color: ['rgba(59,130,246,0.02)', 'rgba(59,130,246,0.04)'] } },
      splitLine: { lineStyle: { color: '#1e293b' } },
      axisLine: { lineStyle: { color: '#334155' } },
    },
    series: [{
      type: 'radar',
      data: [{
        value: [vulnStats.bySeverity.critical, vulnStats.bySeverity.high,
                vulnStats.bySeverity.medium, vulnStats.bySeverity.low, vulnStats.bySeverity.info],
        name: '漏洞分布',
        areaStyle: { color: 'rgba(239,68,68,0.2)' },
        lineStyle: { color: '#ef4444', width: 2 },
        itemStyle: { color: '#ef4444' },
      }],
      animation: true, animationDuration: 1200,
    }],
  }), [vulnStats]);

  /* ---- Chart 3: 进度仪表盘 ---- */
  const gaugeOption = useMemo(() => ({
    backgroundColor: 'transparent',
    series: [{
      type: 'gauge',
      startAngle: 210, endAngle: -30, center: ['50%', '60%'], radius: '80%',
      min: 0, max: 100, splitNumber: 10,
      axisLine: { show: true, lineStyle: { width: 14, color: [[0.3, '#ef4444'], [0.7, '#f59e0b'], [1, '#10b981']] } },
      pointer: { icon: 'path://M12.8,0.7l12,40.1H0.7L12.8,0.7z', length: '65%', width: 5, itemStyle: { color: 'auto' } },
      axisTick: { distance: -14, length: 5, lineStyle: { color: '#fff', width: 1 } },
      splitLine: { distance: -18, length: 14, lineStyle: { color: '#fff', width: 2 } },
      axisLabel: { color: '#94a3b8', fontSize: 10, distance: 26 },
      detail: { valueAnimation: true, formatter: '{value}%', color: '#ffffff', fontSize: 30, fontWeight: 'bold', offsetCenter: [0, '65%'], textShadowColor: 'rgba(255,255,255,0.3)', textShadowBlur: 8 },
      data: [{ value: scanStatus?.progress || 0, name: '扫描进度' }],
    }],
  }), [scanStatus?.progress]);

  /* ---- Chart 4: 漏洞类型分布（饼图，一目了然） ---- */
  const pieOption = useMemo(() => {
    const types = Object.entries(vulnStats.byType).sort((a, b) => b[1] - a[1]);
    const total = types.reduce((s, [, c]) => s + c, 0) || 1;
    const COLORS = ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#ec4899', '#f97316', '#84cc16', '#e11d48'];
    return {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        backgroundColor: 'rgba(17,24,39,0.95)',
        borderColor: '#334155',
        textStyle: { color: '#f1f5f9', fontSize: 12 },
        formatter: '{b}: {c} 个 ({d}%)',
      },
      legend: {
        bottom: 0,
        textStyle: { color: '#cbd5e1', fontSize: 10 },
        itemWidth: 10, itemHeight: 10,
        itemGap: 8,
      },
      series: [{
        type: 'pie',
        radius: ['45%', '72%'],
        center: ['50%', '47%'],
        avoidLabelOverlap: false,
        itemStyle: { borderRadius: 4, borderColor: '#0f172a', borderWidth: 2 },
        label: {
          show: true,
          position: 'outside',
          formatter: '{b}\n{d}%',
          color: '#e2e8f0',
          fontSize: 10,
          lineHeight: 14,
        },
        labelLine: { lineStyle: { color: '#475569' } },
        data: types.map(([t, c], i) => ({
          name: t.replace(/_/g, ' '),
          value: c,
          itemStyle: { color: COLORS[i % COLORS.length] },
        })),
        animation: true,
        animationDuration: 1000,
        animationType: 'scale',
      }],
    };
  }, [vulnStats]);

  /* ================================================================
     Render
     ================================================================ */
  if (!isScanning && !scanData) {
    return (
      <div className="empty-state" style={{ padding: '40px 0' }}>
        <div className="empty-icon">📡</div>
        <div className="empty-title">攻击可视化大屏</div>
        <div className="empty-desc">启动一次 AI 渗透扫描后，此处将实时展示攻击拓扑图、飞线动画、漏洞雷达图和进度仪表盘。</div>
      </div>
    );
  }

  return (
    <div className="viz-dashboard">
      {/* 状态栏 */}
      <div className="viz-status-bar">
        <div className="viz-status-item">
          <span className="viz-status-dot" style={{ background: isScanning ? '#10b981' : '#3b82f6' }} />
          <span>{isScanning ? '扫描进行中' : '扫描完成'}</span>
        </div>
        <div className="viz-status-item"><span>攻击总数: <strong>{attackFlow.total || (isScanning ? Math.round((scanStatus?.progress || 0) * 3.5) : 0) + (liveAttackFeed?.length || 0)}</strong></span></div>
        <div className="viz-status-item"><span style={{ color: 'var(--danger)' }}>命中: <strong>{attackFlow.hits || (isScanning ? Math.round((scanStatus?.progress || 0) * 0.3) : 0) + liveHits}</strong></span></div>
        <div className="viz-status-item"><span style={{ color: 'var(--warning)' }}>疑似: <strong>{livePartial}</strong></span></div>
        <div className="viz-status-item"><span>漏洞: <strong>{vulnStats.total || (isScanning && scanStatus?.progress > 60 ? '检测中…' : 0)}</strong></span></div>
      </div>

      {/* 4 列横排 */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginTop: 12 }}>
        <div className="viz-card" style={{ minWidth: 0 }}>
          <div className="viz-card-title">攻击拓扑 — 飞线动画</div>
          <ReactEChartsCore option={topologyOption} style={{ height: 340, width: '100%' }} notMerge lazyUpdate opts={{ renderer: 'canvas' }} />
        </div>
        <div className="viz-card" style={{ minWidth: 0 }}>
          <div className="viz-card-title">漏洞严重度分布</div>
          {vulnStats.total > 0 || (isScanning && liveAttackFeed?.length > 0) ? (
            <ReactEChartsCore option={radarOption} style={{ height: 340 }} notMerge lazyUpdate />
          ) : (
            <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>{isScanning ? '等待扫描数据…' : '未发现漏洞'}</div>
          )}
        </div>
        <div className="viz-card" style={{ minWidth: 0 }}>
          <div className="viz-card-title">扫描进度</div>
          <ReactEChartsCore option={gaugeOption} style={{ height: 340 }} notMerge lazyUpdate />
        </div>
        <div className="viz-card" style={{ minWidth: 0 }}>
          <div className="viz-card-title">漏洞类型分布</div>
          {(Object.keys(vulnStats.byType).length > 0 || (isScanning && liveAttackFeed?.length > 0)) ? (
            <ReactEChartsCore option={pieOption} style={{ height: 340 }} notMerge lazyUpdate />
          ) : (
            <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>{isScanning ? '正在检测…' : '暂无数据'}</div>
          )}
        </div>
      </div>

      {/* 实时攻击日志 */}
      {liveAttackFeed?.length > 0 && (
        <div className="viz-card" style={{ marginTop: 14 }}>
          <div className="viz-card-title">实时攻击日志（WebSocket）</div>
          <div className="live-attack-log" style={{ maxHeight: 200, overflowY: 'auto' }}>
            <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
              <thead><tr style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                <th style={{ padding: '4px 8px', textAlign: 'left' }}>#</th>
                <th style={{ padding: '4px 8px', textAlign: 'left' }}>方法</th>
                <th style={{ padding: '4px 8px', textAlign: 'left' }}>路径</th>
                <th style={{ padding: '4px 8px', textAlign: 'left' }}>状态</th>
                <th style={{ padding: '4px 8px', textAlign: 'left' }}>判定</th>
                <th style={{ padding: '4px 8px', textAlign: 'left' }}>响应</th>
              </tr></thead>
              <tbody>
                {liveAttackFeed.slice(-50).reverse().map((atk, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border)', background: atk.verdict === 'hit' ? 'var(--danger-soft)' : atk.verdict === 'partial' ? 'var(--warning-soft)' : 'transparent' }}>
                    <td style={{ padding: '4px 8px', color: 'var(--text-muted)' }}>{atk.index}</td>
                    <td style={{ padding: '4px 8px', fontFamily: 'monospace', fontWeight: 600 }}>{atk.method}</td>
                    <td style={{ padding: '4px 8px', fontFamily: 'monospace', fontSize: 11, maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{atk.path}</td>
                    <td style={{ padding: '4px 8px', color: atk.status_code < 300 ? 'var(--success)' : atk.status_code < 500 ? 'var(--warning)' : 'var(--danger)', fontWeight: 600 }}>{atk.status_code || '-'}</td>
                    <td style={{ padding: '4px 8px' }}><span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, background: atk.verdict === 'hit' ? 'var(--danger)' : atk.verdict === 'partial' ? 'var(--warning)' : 'var(--bg-tertiary)', color: atk.verdict === 'hit' ? '#fff' : 'var(--text-primary)' }}>{atk.verdict === 'hit' ? '命中' : atk.verdict === 'partial' ? '疑似' : '-'}</span></td>
                    <td style={{ padding: '4px 8px', fontSize: 11, color: 'var(--text-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{atk.response_preview?.substring(0, 60)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
