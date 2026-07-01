import { useState, useCallback, useEffect, useRef } from 'react';
import './App.css';
import { io } from 'socket.io-client';
import { ThemeProvider } from './components/ThemeProvider';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import ResultCard from './components/ResultCard';
import BusinessAnalysis from './components/BusinessAnalysis';
import AttackPlans from './components/AttackPlans';
import ExecutionResults from './components/ExecutionResults';
import ResultAnalysis from './components/ResultAnalysis';
import SecurityAssessment from './components/SecurityAssessment';
import ScanComparison from './components/ScanComparison';
import Dashboard from './components/Dashboard';
import Pricing from './components/Pricing';
import ShadowApi from './components/ShadowApi';
import CaseStudies from './components/CaseStudies';
import AttackVisualization from './components/AttackVisualization';
import { API_BASE, VERDICT } from './components/helpers';

const TABS = [
  { key: 'dashboard', label: '📊 仪表盘' },
  { key: 'scanner', label: '🔍 安全扫描' },
  { key: 'visualization', label: '🗺️ 可视化大屏' },
  { key: 'shadow', label: '🕵️ 影子API发现' },
  { key: 'cases', label: '📋 测试案例' },
  { key: 'pricing', label: '💎 方案定价' },
];

/* ============================================================
   Main App — thin orchestrator
   ============================================================ */
export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isScanning, setIsScanning] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [error, setError] = useState(null);
  const [modelInfo, setModelInfo] = useState('DeepSeek');
  const [externalScanId, setExternalScanId] = useState(null);
  // v3.3: WebSocket 实时攻击流
  const [liveAttackFeed, setLiveAttackFeed] = useState([]);
  const [liveVulnSummary, setLiveVulnSummary] = useState(null);
  const socketRef = useRef(null);
  const activeScanIdRef = useRef(null);

  // ---- Setup WebSocket connection ----
  useEffect(() => {
    const WS_URL = API_BASE.replace(/^http/, 'ws');
    const socket = io(`${WS_URL}/ws`, {
      transports: ['websocket', 'polling'],
      path: '/socket.io',
    });
    socketRef.current = socket;

    socket.on('connect', () => {
      console.log('[WS] Connected:', socket.id);
    });

    socket.on('disconnect', () => {
      console.log('[WS] Disconnected');
    });

    // Listen for scan status updates
    socket.on('scan_status', (data) => {
      if (data.scan_id !== activeScanIdRef.current) return;
      setScanStatus({
        status: data.status,
        phase: data.phase,
        message: data.message,
        progress: data.progress,
      });
      if (data.status === 'failed') {
        setError(data.message || '扫描执行失败');
        setIsScanning(false);
      }
    });

    // Listen for live attack results
    socket.on('attack_result', (data) => {
      if (activeScanIdRef.current) {
        setLiveAttackFeed((prev) => [...prev.slice(-99), data]);
      }
    });

    // Listen for scan completion
    socket.on('scan_complete', async (data) => {
      if (data.scan_id !== activeScanIdRef.current) return;
      setLiveVulnSummary(data);
      // Fetch full scan data
      try {
        const fullRes = await fetch(`${API_BASE}/scans/${data.scan_id}`);
        const fullData = await fullRes.json();
        if (fullData.success) {
          setScanData(fullData.scan);
          console.log('[scan_complete] 完整数据已加载, 漏洞数:',
            fullData.scan?.data?.security_assessment?.vulnerabilities_found?.length);
        }
      } catch (e) { console.warn('[scan_complete] 获取完整数据失败:', e); }
      setIsScanning(false);
      setLiveAttackFeed([]);
      // 清除轮询
      if (window.__smartAttackPollTimer) {
        clearInterval(window.__smartAttackPollTimer);
      }
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  // ---- Handle external scan ID (from Shadow API page) ----
  useEffect(() => {
    if (!externalScanId) return;

    setIsScanning(true);
    setScanData(null);
    setScanStatus({ status: 'queued', phase: 'pending', message: '影子 API 扫描已提交…' });
    setError(null);
    setLiveAttackFeed([]);
    setLiveVulnSummary(null);
    activeScanIdRef.current = externalScanId;

    // Subscribe via WebSocket
    if (socketRef.current?.connected) {
      socketRef.current.emit('subscribe_scan', { scan_id: externalScanId });
    } else {
      // Fallback: wait for connection then subscribe
      const onConnect = () => {
        socketRef.current?.emit('subscribe_scan', { scan_id: externalScanId });
      };
      socketRef.current?.once('connect', onConnect);
    }
  }, [externalScanId]);

  // ---- Start Scan (WebSocket-driven) ----
  const handleScanStart = useCallback(async (body) => {
    setIsScanning(true);
    setScanData(null);
    setScanStatus(null);
    setError(null);
    setLiveAttackFeed([]);
    setLiveVulnSummary(null);

    try {
      const response = await fetch(`${API_BASE}/start_scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (!data.success) {
        setError(data.error || '扫描失败');
        setIsScanning(false);
        return;
      }

      setModelInfo(data.model_provider || body.model_provider || 'DeepSeek');
      // 无论何种模式，扫描启动后立即跳转到可视化大屏
      setActiveTab('visualization');

      if (data.mode === 'async' || data.status === 'queued') {
        setScanStatus({ status: 'queued', phase: 'pending', message: '等待执行…', progress: 0 });
        setIsScanning(true);
        activeScanIdRef.current = data.scan_id;

        // Subscribe to scan room via WebSocket
        if (socketRef.current?.connected) {
          socketRef.current.emit('subscribe_scan', { scan_id: data.scan_id });
        } else {
          socketRef.current?.once('connect', () => {
            socketRef.current?.emit('subscribe_scan', { scan_id: data.scan_id });
          });
        }

        // 轮询兜底：每 3 秒查进度 + 完成后自动拉取完整数据
        window.__smartAttackPollTimer = setInterval(async () => {
          try {
            const res = await fetch(`${API_BASE}/scans/${data.scan_id}/status`);
            const s = await res.json();
            if (s.success) {
              setScanStatus({
                status: s.status || 'running',
                phase: s.phase || '',
                message: s.message || '',
                progress: s.progress || 0,
              });
              // 扫描完成 → 拉取完整数据填充图表
              if (s.status === 'completed' || s.status === 'failed') {
                clearInterval(window.__smartAttackPollTimer);
                try {
                  const fullRes = await fetch(`${API_BASE}/scans/${data.scan_id}`);
                  const fullData = await fullRes.json();
                  if (fullData.success) {
                    setScanData(fullData.scan);
                    setIsScanning(false);
                  }
                } catch { /* ignore */ }
              }
            }
          } catch { /* ignore */ }
        }, 3000);
      } else {
        // Sync mode — 模拟进度步骤（因为没有 WebSocket）
        setIsScanning(true);
        const steps = [
          { progress: 10, message: '正在抓取 Swagger 文档…', phase: 'fetch' },
          { progress: 30, message: 'AI 正在分析业务逻辑…', phase: 'analyze' },
          { progress: 60, message: '正在执行攻击…', phase: 'attack' },
          { progress: 85, message: 'AI 正在分析结果…', phase: 'evaluate' },
          { progress: 100, message: '扫描完成', phase: 'done' },
        ];
        let i = 0;
        const timer = setInterval(() => {
          if (i < steps.length) {
            setScanStatus({ status: 'running', ...steps[i] });
            i++;
          } else {
            clearInterval(timer);
          }
        }, 600);
        // 拿到完整数据后
        setScanData(data);
        setTimeout(() => {
          clearInterval(timer);
          setScanStatus({ status: 'completed', phase: 'done', message: '扫描完成', progress: 100 });
          setIsScanning(false);
        }, 800);
      }
    } catch (err) {
      setError(`无法连接到后端引擎：${err.message}`);
      setIsScanning(false);
    }
  }, []);

  // ---- Select scan from history ----
  const handleSelectScan = useCallback(async (scanId) => {
    if (scanId.startsWith('compare:')) {
      const [, idA, idB] = scanId.split(':');
      setScanData({ _compare: true, scanIdA: idA, scanIdB: idB });
      return;
    }
    setScanData(null);
    setError(null);
    setIsScanning(true);
    try {
      const res = await fetch(`${API_BASE}/scans/${scanId}`);
      const data = await res.json();
      if (data.success) {
        setScanData(data.scan);
        setScanStatus(null);
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError(`获取扫描详情失败：${err.message}`);
    } finally {
      setIsScanning(false);
    }
  }, []);

  // ---- Navigate to tab ----
  const handleNavigate = useCallback((tab, scanId) => {
    setActiveTab(tab);
    if (tab === 'scanner' && scanId) {
      setExternalScanId(scanId);
    }
    if (tab !== 'scanner') {
      // Unsubscribe from current scan room
      if (activeScanIdRef.current && socketRef.current?.connected) {
        socketRef.current.emit('unsubscribe_scan', { scan_id: activeScanIdRef.current });
      }
      setIsScanning(false);
      setExternalScanId(null);
      setLiveAttackFeed([]);
    }
  }, []);

  /* ---- Derived counts ---- */
  const data = scanData?.data || scanData;
  const phase1Count = scanData?.stats?.phase1_plan_count ?? data?.attack_plans?.length ?? 0;
  const phase1Exec = scanData?.stats?.phase1_executed ?? data?.execution_results?.length ?? 0;
  const phase2Count = scanData?.stats?.phase2_plan_count ?? data?.followup_plans?.length ?? 0;
  const phase2Exec = scanData?.stats?.phase2_executed ?? data?.followup_execution?.length ?? 0;
  const hitCount = data?.execution_results
    ? data.execution_results.filter((r) => VERDICT(r).verdict === 'hit').length
    : 0;
  const overallRating = data?.security_assessment?.overall_rating || 'unknown';

  // Comparison mode (overlays scanner tab)
  if (scanData?._compare) {
    return (
      <ThemeProvider>
        <div className="app-root">
          <Header isScanning={false} modelInfo={modelInfo} />
          {/* Tab bar */}
          <nav className="tab-bar">
            {TABS.map((t) => (
              <button
                key={t.key}
                className={`tab-item ${activeTab === t.key ? 'active' : ''}`}
                onClick={() => handleNavigate(t.key)}
              >
                {t.label}
              </button>
            ))}
          </nav>
          <div className="app-main">
            <Sidebar
              isScanning={false} scanData={null} scanStatus={null} error={null}
              onScanStart={handleScanStart} onSelectScan={handleSelectScan}
            />
            <main className="content-area">
              <ScanComparison
                scanIdA={scanData.scanIdA}
                scanIdB={scanData.scanIdB}
                onClose={() => setScanData(null)}
              />
            </main>
          </div>
        </div>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider>
      <div className="app-root">
        {/* ======== Header ======== */}
        <Header isScanning={isScanning} modelInfo={modelInfo} />

        {/* ======== Tab Navigation ======== */}
        <nav className="tab-bar">
          {TABS.map((t) => (
            <button
              key={t.key}
              className={`tab-item ${activeTab === t.key ? 'active' : ''}`}
              onClick={() => handleNavigate(t.key)}
            >
              {t.label}
            </button>
          ))}
        </nav>

        {/* ======== DASHBOARD TAB ======== */}
        {activeTab === 'dashboard' && (
          <main className="content-area" style={{ padding: '24px 28px' }}>
            <Dashboard onNavigate={handleNavigate} />
          </main>
        )}

        {/* ======== PRICING TAB ======== */}
        {activeTab === 'pricing' && (
          <main className="content-area" style={{ padding: '24px 28px' }}>
            <Pricing onNavigate={handleNavigate} />
          </main>
        )}

        {/* ======== SHADOW API TAB ======== */}
        {activeTab === 'shadow' && (
          <main className="content-area" style={{ padding: '24px 28px' }}>
            <ShadowApi onNavigate={handleNavigate} />
          </main>
        )}

        {/* ======== CASE STUDIES TAB ======== */}
        {activeTab === 'cases' && (
          <main className="content-area" style={{ padding: '24px 28px' }}>
            <CaseStudies />
          </main>
        )}

        {/* ======== VISUALIZATION TAB ======== */}
        {activeTab === 'visualization' && (
          <main className="content-area" style={{ padding: '24px 28px' }}>
            <AttackVisualization
              scanData={scanData}
              liveAttackFeed={liveAttackFeed}
              scanStatus={scanStatus}
              isScanning={isScanning}
            />
          </main>
        )}

        {/* ======== SCANNER TAB ======== */}
        {activeTab === 'scanner' && (
          <div className="app-main">
            <Sidebar
              isScanning={isScanning}
              scanData={scanData}
              scanStatus={scanStatus}
              error={error}
              onScanStart={handleScanStart}
              onSelectScan={handleSelectScan}
            />

            <main className="content-area">
              {/* Error */}
              {error && (
                <div className="result-card" style={{ borderColor: 'var(--danger)' }}>
                  <div className="result-card-header" style={{ cursor: 'default' }}>
                    <div className="card-title-group">
                      <div className="card-icon" style={{ background: 'var(--danger-soft)' }}>❌</div>
                      <div><div className="card-title" style={{ color: 'var(--danger)' }}>错误</div></div>
                    </div>
                  </div>
                  <div className="result-card-body open">
                    <div className="remediation-box" style={{ color: 'var(--danger)', marginTop: 0 }}>{error}</div>
                  </div>
                </div>
              )}

              {/* Scanning indicator — sync */}
              {isScanning && !scanStatus && (
                <div className="scan-progress">
                  <span className="scan-spinner" />
                  <span className="scan-text">AI 正在深度分析 API 业务逻辑并生成攻击方案…</span>
                </div>
              )}

              {/* Scanning indicator — async (WebSocket 实时推送) */}
              {isScanning && scanStatus && (
                <div className="scan-progress-container">
                  <div className="scan-progress">
                    <span className={`scan-spinner ${scanStatus.status === 'failed' ? 'done' : ''}`} />
                    <span className="scan-text" style={{ color: scanStatus.status === 'failed' ? 'var(--danger)' : 'var(--accent)' }}>
                      {scanStatus.message}
                    </span>
                  </div>

                  {/* Progress bar */}
                  <div className="progress-bar-track" style={{ marginTop: 12 }}>
                    <div
                      className={`progress-bar-fill ${scanStatus.status === 'failed' ? 'failed' : ''}`}
                      style={{ width: `${scanStatus.status === 'completed' ? 100 : (scanStatus.progress || 0)}%` }}
                    />
                  </div>

                  {/* Phase indicators */}
                  <div className="phase-legend" style={{ marginTop: 12 }}>
                    {[
                      { key: 'fetch', label: '抓取 Swagger' },
                      { key: 'analyze', label: 'AI 分析' },
                      { key: 'attack', label: '攻击执行' },
                      { key: 'evaluate', label: '结果评估' },
                      { key: 'followup', label: '后续攻击' },
                      { key: 'done', label: '完成' },
                    ].map((phase) => {
                      const activePhase = scanStatus.phase;
                      const phases = ['fetch', 'analyze', 'attack', 'evaluate', 'followup', 'done'];
                      const currentIdx = phases.indexOf(activePhase);
                      const phaseIdx = phases.indexOf(phase.key);
                      let cls = '';
                      if (currentIdx >= 0 && phaseIdx < currentIdx) cls = 'done';
                      else if (phaseIdx === currentIdx && scanStatus.status !== 'failed') cls = 'active';
                      return (
                        <div key={phase.key} className={`phase-step ${cls}`}>
                          <span className="phase-dot" />
                          <span>{phase.label}</span>
                        </div>
                      );
                    })}
                  </div>

                  {/* Live attack feed */}
                  {liveAttackFeed.length > 0 && (
                    <div className="live-attack-feed" style={{ marginTop: 16 }}>
                      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600 }}>
                        ⚡ 实时攻击流 ({liveAttackFeed.length} 条)
                      </div>
                      <div style={{ maxHeight: 200, overflowY: 'auto', fontSize: 12 }}>
                        {liveAttackFeed.slice(-20).reverse().map((atk, i) => (
                          <div
                            key={i}
                            style={{
                              display: 'flex', alignItems: 'center', gap: 8,
                              padding: '4px 8px', borderRadius: 4,
                              marginBottom: 2,
                              background: atk.verdict === 'hit'
                                ? 'var(--danger-soft)'
                                : atk.verdict === 'partial'
                                  ? 'var(--warning-soft)'
                                  : 'var(--bg-secondary)',
                            }}
                          >
                            <span style={{
                              minWidth: 28, textAlign: 'center', fontWeight: 600, fontSize: 10,
                              color: atk.verdict === 'hit' ? 'var(--danger)'
                                : atk.verdict === 'partial' ? 'var(--warning)' : 'var(--text-muted)',
                            }}>
                              {atk.index}/{atk.total}
                            </span>
                            <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-primary)' }}>
                              {atk.method}
                            </span>
                            <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {atk.path}
                            </span>
                            <span style={{
                              minWidth: 44, textAlign: 'center', fontSize: 11,
                              color: atk.status_code < 300 ? 'var(--success)' : atk.status_code < 500 ? 'var(--warning)' : 'var(--danger)',
                            }}>
                              {atk.status_code || '—'}
                            </span>
                            <span style={{
                              minWidth: 48, textAlign: 'center', fontSize: 10,
                              padding: '1px 6px', borderRadius: 3,
                              background: atk.verdict === 'hit' ? 'var(--danger)' : atk.verdict === 'partial' ? 'var(--warning)' : 'var(--bg-tertiary)',
                              color: atk.verdict === 'hit' ? '#fff' : 'var(--text-primary)',
                            }}>
                              {atk.verdict === 'hit' ? '🔥 命中' : atk.verdict === 'partial' ? '⚠ 泄露' : '—'}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Vulnerability summary on complete */}
                  {liveVulnSummary && (
                    <div style={{
                      marginTop: 16, padding: 16, borderRadius: 8,
                      background: liveVulnSummary.hits > 0 ? 'var(--danger-soft)' : 'var(--success-soft)',
                      border: `1px solid ${liveVulnSummary.hits > 0 ? 'var(--danger)' : 'var(--success)'}`,
                    }}>
                      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
                        {liveVulnSummary.hits > 0 ? '🚨 发现漏洞！' : '✅ 扫描完成'}
                      </div>
                      <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                        共执行 {liveVulnSummary.total_attacks} 组攻击，
                        发现 {liveVulnSummary.vulnerabilities_count} 个潜在漏洞，
                        安全评级：
                        <span style={{
                          fontWeight: 600,
                          color: liveVulnSummary.overall_rating === 'high' ? 'var(--danger)'
                            : liveVulnSummary.overall_rating === 'medium' ? 'var(--warning)' : 'var(--success)',
                        }}>
                          {liveVulnSummary.overall_rating?.toUpperCase()}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Empty state */}
              {!scanData && !isScanning && !error && (
                <div className="empty-state">
                  <div className="empty-icon">🛡️</div>
                  <div className="empty-title">准备就绪</div>
                  <div className="empty-desc">
                    在左侧输入目标 API 的 Swagger / OpenAPI 文档地址，然后点击「启动 AI 渗透扫描」。
                    系统将自动完成业务逻辑分析、攻击载荷生成、并发执行和结果评估。
                  </div>
                </div>
              )}

              {/* ======== Results ======== */}
              {scanData && (
                <>
                  <ResultCard
                    icon="🔍" iconClass="analysis"
                    title="Phase 1: AI 业务逻辑深度分析"
                    subtitle={`领域：${data?.business_analysis?.domain || '未识别'} | 实体：${data?.business_analysis?.entities?.length || 0} 个 | 攻击面：${data?.business_analysis?.vulnerability_surface?.length || 0} 处`}
                    badge={`${phase1Count} 组攻击方案`}
                    badgeClass="info"
                  >
                    <BusinessAnalysis analysis={data?.business_analysis} />
                  </ResultCard>

                  <ResultCard
                    icon="🎯" iconClass="attack"
                    title="Phase 1: AI 攻击方案"
                    subtitle={`共 ${phase1Count} 组针对性攻击载荷`}
                    badge={phase1Count > 0 ? `${phase1Count} 组` : '无'}
                    badgeClass="warn" defaultOpen={false}
                  >
                    <AttackPlans plans={data?.attack_plans} title="第一轮攻击方案" />
                  </ResultCard>

                  <ResultCard
                    icon="⚔️" iconClass="result"
                    title="Phase 2: 攻击执行结果"
                    subtitle={`${phase1Exec} 次请求 | ${hitCount} 次潜在命中`}
                    badge={hitCount > 0 ? `🔥 ${hitCount} 命中` : '无命中'}
                    badgeClass={hitCount > 0 ? 'danger' : 'success'}
                  >
                    <ExecutionResults results={data?.execution_results} title="第一轮攻击执行" plans={data?.attack_plans} />
                  </ResultCard>

                  {data?.result_analysis && Object.keys(data.result_analysis).length > 0 && (
                    <ResultCard
                      icon="🧠" iconClass="assess"
                      title="Phase 3: AI 响应分析"
                      subtitle={data.result_analysis.summary || ''}
                      badge={data.result_analysis.defense_level
                        ? `防御: ${data.result_analysis.defense_level.toUpperCase()}`
                        : '分析完成'}
                      badgeClass="warn"
                    >
                      <ResultAnalysis analysis={data.result_analysis} />
                    </ResultCard>
                  )}

                  {data?.followup_plans && data.followup_plans.length > 0 && (
                    <>
                      <ResultCard
                        icon="🔁" iconClass="attack"
                        title="Phase 4: AI 精炼后续攻击方案"
                        subtitle={`基于第一轮结果，生成 ${phase2Count} 组精炼攻击`}
                        badge={`${phase2Count} 组`} badgeClass="warn" defaultOpen={false}
                      >
                        <AttackPlans plans={data.followup_plans} title="后续精炼攻击方案" />
                      </ResultCard>
                      {data?.followup_execution && data.followup_execution.length > 0 && (
                        <ResultCard
                          icon="⚔️" iconClass="result"
                          title="后续攻击执行结果" subtitle={`${phase2Exec} 次请求`}
                          badge={`${phase2Exec} 次`} badgeClass="info" defaultOpen={false}
                        >
                          <ExecutionResults results={data.followup_execution} title="后续攻击执行" plans={data?.followup_plans} />
                        </ResultCard>
                      )}
                    </>
                  )}

                  {data?.security_assessment && Object.keys(data.security_assessment).length > 0 && (
                    <ResultCard
                      icon="🏁" iconClass="assess"
                      title="最终安全评估"
                      subtitle={`评级：${overallRating.toUpperCase()}`}
                      badge={overallRating.toUpperCase()}
                      badgeClass={overallRating === 'high' ? 'danger' : overallRating === 'medium' ? 'warn' : 'success'}
                    >
                      <SecurityAssessment assessment={data.security_assessment} />
                    </ResultCard>
                  )}
                </>
              )}
            </main>
          </div>
        )}
      </div>
    </ThemeProvider>
  );
}
