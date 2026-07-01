import { useState } from 'react';
import { STATUS_CLASS, VERDICT, SEVERITY_COLOR } from './helpers';
import AttackReplay from './AttackReplay';

export default function ExecutionResults({ results, title, plans }) {
  const [viewMode, setViewMode] = useState('table'); // 'table' | 'replay'

  if (!results || results.length === 0) return <p style={{ color: 'var(--text-muted)' }}>无执行结果</p>;

  const hits = results.filter((r) => VERDICT(r).verdict === 'hit').length;

  return (
    <div>
      {/* 视图切换工具栏 */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        {title && <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-secondary)', margin: 0 }}>{title}</h3>}
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            className={`btn btn-sm ${viewMode === 'table' ? 'btn-primary' : ''}`}
            onClick={() => setViewMode('table')}
            style={{ fontSize: 11 }}
          >
            📋 表格视图
          </button>
          <button
            className={`btn btn-sm ${viewMode === 'replay' ? 'btn-primary' : ''}`}
            onClick={() => setViewMode('replay')}
            style={{ fontSize: 11 }}
          >
            🔍 攻击回放 ({hits} 命中)
          </button>
        </div>
      </div>

      {viewMode === 'table' ? (
        <div style={{ overflowX: 'auto' }}>
          <table className="execution-table">
            <thead>
              <tr>
                <th>#</th>
                <th>方法</th>
                <th>路径</th>
                <th>漏洞类型</th>
                <th>状态码</th>
                <th>判定</th>
                <th>响应预览</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => {
                const v = VERDICT(r);
                const method = (r.payload?.method || r.method || 'GET').toUpperCase();
                const path = r.payload?.path || r.path || '/';
                return (
                  <tr key={i}>
                    <td style={{ color: 'var(--text-muted)' }}>{r.round || i + 1}</td>
                    <td><span className={`plan-method ${method}`}>{method}</span></td>
                    <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{path}</td>
                    <td>
                      <span className={`card-badge ${SEVERITY_COLOR(r.vulnerability_type)}`}>
                        {r.vulnerability_type || 'unknown'}
                      </span>
                    </td>
                    <td>
                      <span className={`status-code ${STATUS_CLASS(r.status_code)}`}>
                        {r.status_code || 'ERR'}
                      </span>
                    </td>
                    <td>
                      <span className={`verdict-chip ${v.verdict}`}>{v.label}</span>
                    </td>
                    <td>
                      <div className="response-preview" title={r.response_text}>
                        {(r.response_text || '').substring(0, 100)}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <AttackReplay results={results} plans={plans} title={title} />
      )}
    </div>
  );
}
