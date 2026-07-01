import { useState, useMemo } from 'react';
import { VERDICT, SEVERITY_COLOR, API_BASE } from './helpers';

/* ============================================================
   AttackReplay — 攻击回放 & 详情查看
   - 点击漏洞查看完整请求/响应
   - 生成 curl 命令
   - 支持重新执行攻击
   ============================================================ */

export default function AttackReplay({ results, title, plans }) {
  const [selectedIdx, setSelectedIdx] = useState(null);
  const [replayStatus, setReplayStatus] = useState(null);
  const [replaying, setReplaying] = useState(false);

  const items = useMemo(() => {
    if (!results || results.length === 0) return [];
    return results.map((r, i) => {
      const plan = plans?.[i] || plans?.[r.plan_index];
      return {
        ...r,
        index: i,
        planDescription: plan?.description || plan?.reasoning || '—',
        planVulnType: plan?.vulnerability_type || r?.vulnerability_type || 'unknown',
        verdict: VERDICT(r),
      };
    });
  }, [results, plans]);

  const selected = selectedIdx !== null ? items[selectedIdx] : null;

  /* ---- 重新执行攻击 ---- */
  const handleReplay = async (item) => {
    setReplaying(true);
    setReplayStatus(null);
    try {
      const method = item.method || 'GET';
      const url = item.full_url || item.url || '';
      const headers = item.request_headers || {};
      const body = item.request_body || null;

      const fetchOpts = {
        method,
        headers: { ...headers },
      };
      if (body && method !== 'GET') {
        fetchOpts.body = typeof body === 'string' ? body : JSON.stringify(body);
        if (!fetchOpts.headers['Content-Type']) {
          fetchOpts.headers['Content-Type'] = 'application/json';
        }
      }

      const start = Date.now();
      const res = await fetch(url, fetchOpts);
      const elapsed = Date.now() - start;
      const text = await res.text();

      setReplayStatus({
        status: res.status,
        headers: Object.fromEntries(res.headers.entries()),
        body: text.substring(0, 4000),
        elapsed,
      });
    } catch (err) {
      setReplayStatus({ error: err.message });
    } finally {
      setReplaying(false);
    }
  };

  /* ---- 生成 curl 命令 ---- */
  const buildCurlCmd = (item) => {
    const method = item.method || 'GET';
    const url = item.full_url || item.url || '';
    const headers = item.request_headers || {};
    const body = item.request_body || null;

    let cmd = `curl -X ${method} "${url}"`;
    Object.entries(headers).forEach(([k, v]) => {
      cmd += ` \\\n  -H "${k}: ${v}"`;
    });
    if (body && method !== 'GET') {
      const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
      cmd += ` \\\n  -d '${bodyStr.replace(/'/g, "'\\''")}'`;
    }
    return cmd;
  };

  /* ---- 复制到剪贴板 ---- */
  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
  };

  if (items.length === 0) {
    return <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: 12 }}>暂无攻击数据</div>;
  }

  return (
    <div className="replay-container">
      {/* ======== 攻击列表 ======== */}
      <div className="replay-list">
        <div className="replay-list-header">
          <span>{title || '攻击执行结果'} ({items.length} 组)</span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            🔥 {items.filter((i) => i.verdict.verdict === 'hit').length} 命中 |
            ⚠ {items.filter((i) => i.verdict.verdict === 'partial').length} 疑似
          </span>
        </div>
        {items.map((item) => (
          <button
            key={item.index}
            className={`replay-item ${selectedIdx === item.index ? 'active' : ''}`}
            onClick={() => setSelectedIdx(item.index)}
          >
            <span className={`replay-badge ${item.verdict.verdict}`}>
              {item.verdict.verdict === 'hit' ? '🔥' : item.verdict.verdict === 'partial' ? '⚠' : '—'}
            </span>
            <span className="replay-method">{item.method || 'GET'}</span>
            <span className="replay-path">{item.path || '/'}</span>
            <span className={`replay-status s${Math.floor((item.status_code || 0) / 100)}xx`}>
              {item.status_code || '—'}
            </span>
            <span className={`replay-type-tag ${SEVERITY_COLOR(item.planVulnType)}`}>
              {item.planVulnType?.replace(/_/g, ' ') || 'unknown'}
            </span>
          </button>
        ))}
      </div>

      {/* ======== 详情面板 ======== */}
      <div className="replay-detail">
        {!selected ? (
          <div className="empty-state" style={{ padding: '40px 20px' }}>
            <div className="empty-icon">🔍</div>
            <div className="empty-title">选择一次攻击</div>
            <div className="empty-desc">点击左侧攻击记录查看完整的请求/响应详情</div>
          </div>
        ) : (
          <>
            {/* 摘要 */}
            <div className="replay-detail-header">
              <div>
                <span className={`replay-badge large ${selected.verdict.verdict}`}>
                  {selected.verdict.verdict === 'hit' ? '🔥 命中' : selected.verdict.verdict === 'partial' ? '⚠ 部分泄露' : '未命中'}
                </span>
                <span className="replay-method" style={{ marginLeft: 8 }}>{selected.method || 'GET'}</span>
                <span style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--accent)', marginLeft: 4 }}>
                  {selected.path || '/'}
                </span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  className="btn btn-sm"
                  onClick={() => copyToClipboard(buildCurlCmd(selected))}
                  title="复制 curl 命令"
                >
                  📋 curl
                </button>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={() => handleReplay(selected)}
                  disabled={replaying}
                >
                  {replaying ? '⏳' : '🔄'} 重新执行
                </button>
              </div>
            </div>

            {/* 攻击策略描述 */}
            <div className="replay-section">
              <div className="replay-section-title">🎯 攻击策略</div>
              <div className="replay-section-content">
                <strong>漏洞类型:</strong> {selected.planVulnType?.replace(/_/g, ' ') || 'unknown'}
                <br />
                <strong>描述:</strong> {selected.planDescription}
              </div>
            </div>

            {/* 请求详情 */}
            <div className="replay-section">
              <div className="replay-section-title">📤 请求</div>
              <div className="replay-section-content">
                <div><strong>URL:</strong> <code>{selected.full_url || selected.url || '—'}</code></div>
                <div style={{ marginTop: 4 }}><strong>Headers:</strong></div>
                <pre className="replay-code-block">
                  {JSON.stringify(selected.request_headers || {}, null, 2)}
                </pre>
                {selected.request_body && (
                  <>
                    <div style={{ marginTop: 4 }}><strong>Body:</strong></div>
                    <pre className="replay-code-block">
                      {typeof selected.request_body === 'string'
                        ? selected.request_body.substring(0, 2000)
                        : JSON.stringify(selected.request_body, null, 2).substring(0, 2000)}
                    </pre>
                  </>
                )}
              </div>
            </div>

            {/* 响应详情 */}
            <div className="replay-section">
              <div className="replay-section-title">📥 响应</div>
              <div className="replay-section-content">
                <div>
                  <strong>状态码:</strong>{' '}
                  <span className={`replay-status s${Math.floor((selected.status_code || 0) / 100)}xx`}>
                    {selected.status_code || '—'}
                  </span>
                  {selected.elapsed && (
                    <span style={{ marginLeft: 8, fontSize: 12, color: 'var(--text-muted)' }}>
                      ⏱ {selected.elapsed}s
                    </span>
                  )}
                </div>
                <div style={{ marginTop: 4 }}><strong>响应内容:</strong></div>
                <pre className="replay-code-block replay-response">
                  {(selected.response_text || '(空响应)').substring(0, 4000)}
                </pre>
              </div>
            </div>

            {/* curl 命令 */}
            <div className="replay-section">
              <div className="replay-section-title">💻 curl 命令（可复制重现）</div>
              <pre className="replay-code-block" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                {buildCurlCmd(selected)}
              </pre>
            </div>

            {/* 重新执行结果 */}
            {replayStatus && (
              <div className="replay-section" style={{
                borderColor: replayStatus.error ? 'var(--danger)' : replayStatus.status < 300 ? 'var(--success)' : 'var(--warning)',
              }}>
                <div className="replay-section-title">
                  {replayStatus.error ? '❌ 重放失败' : '✅ 重放完成'}
                  {!replayStatus.error && (
                    <span style={{ marginLeft: 8, fontSize: 12, color: 'var(--text-muted)' }}>
                      ⏱ {replayStatus.elapsed}ms
                    </span>
                  )}
                </div>
                <div className="replay-section-content">
                  {replayStatus.error ? (
                    <div style={{ color: 'var(--danger)' }}>{replayStatus.error}</div>
                  ) : (
                    <>
                      <div>
                        <strong>状态码:</strong>{' '}
                        <span className={`replay-status s${Math.floor((replayStatus.status || 0) / 100)}xx`}>
                          {replayStatus.status}
                        </span>
                      </div>
                      <div style={{ marginTop: 4 }}><strong>响应:</strong></div>
                      <pre className="replay-code-block replay-response">
                        {replayStatus.body?.substring(0, 2000)}
                      </pre>
                    </>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
