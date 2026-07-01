const PHASES = [
  { key: 'fetch', label: '抓取 Swagger' },
  { key: 'analyze', label: 'AI 业务分析' },
  { key: 'attack', label: '攻击执行' },
  { key: 'evaluate', label: '结果评估' },
  { key: 'followup', label: '后续攻击' },
  { key: 'done', label: '完成' },
];

export default function ScanProgress({ status }) {
  if (!status) return null;

  const currentIdx = PHASES.findIndex((p) => p.key === status.phase);
  const isDone = status.status === 'completed';
  const isFailed = status.status === 'failed';
  const progress = status.progress || 0;

  return (
    <div className="scan-progress-container">
      <div className="scan-progress-header">
        <span className={`scan-spinner ${isDone || isFailed ? 'done' : ''}`} />
        <span className="scan-text" style={{ color: isFailed ? 'var(--danger)' : 'var(--accent)' }}>
          {isDone ? '扫描完成 ✅' : isFailed ? '扫描失败 ❌' : status.message}
        </span>
      </div>

      {/* Progress bar */}
      <div className="progress-bar-track">
        <div
          className={`progress-bar-fill ${isFailed ? 'failed' : ''}`}
          style={{ width: `${isDone ? 100 : progress}%` }}
        />
      </div>

      {/* Phase indicators */}
      <div className="phase-legend" style={{ marginTop: 12 }}>
        {PHASES.map((phase, idx) => {
          let cls = '';
          if (isDone || idx < currentIdx) cls = 'done';
          else if (idx === currentIdx && !isFailed) cls = 'active';
          return (
            <div key={phase.key} className={`phase-step ${cls}`}>
              <span className="phase-dot" />
              <span>{phase.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
