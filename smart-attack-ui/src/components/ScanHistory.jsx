import { useState, useEffect } from 'react';
import { API_BASE } from './helpers';

export default function ScanHistory({ onSelectScan, onCompareScans, selectedIds }) {
  const [scans, setScans] = useState([]);
  const [search, setSearch] = useState('');
  const [filterRating, setFilterRating] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: '50' });
    if (search) params.set('search', search);
    if (filterRating) params.set('rating', filterRating);

    fetch(`${API_BASE}/scans?${params}`)
      .then((r) => r.json())
      .then((d) => {
        if (d.success) setScans(d.scans || []);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [search, filterRating]);

  const ratings = ['all', 'high', 'medium', 'low'];

  return (
    <div className="scan-history-section">
      <div className="sidebar-section-title">扫描历史</div>

      <input
        type="text"
        className="model-select-input"
        placeholder="搜索 URL…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        style={{ marginBottom: 8 }}
      />

      <div className="filter-chips">
        {ratings.map((r) => (
          <button
            key={r}
            className={`chip ${filterRating === r || (r === 'all' && !filterRating) ? 'active' : ''}`}
            onClick={() => setFilterRating(r === 'all' ? '' : r)}
          >
            {r === 'all' ? '全部' : r.toUpperCase()}
          </button>
        ))}
      </div>

      <div className="scan-list">
        {loading && <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: 8 }}>加载中…</div>}
        {!loading && scans.length === 0 && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: 8 }}>暂无扫描记录</div>
        )}
        {scans.map((s) => (
          <div
            key={s.scan_id}
            className={`scan-item ${selectedIds?.includes(s.scan_id) ? 'selected' : ''}`}
            onClick={() => onSelectScan?.(s.scan_id)}
          >
            <div className="scan-item-url" title={s.target_url}>{s.target_url}</div>
            <div className="scan-item-meta">
              <span>{s.created_at ? new Date(s.created_at).toLocaleDateString() : ''}</span>
              <span className={`rating-badge-sm ${s.overall_rating || 'unknown'}`}>
                {s.overall_rating?.toUpperCase() || '?'}
              </span>
              {s.status && s.status !== 'completed' && (
                <span className={`card-badge ${s.status === 'failed' ? 'danger' : 'warn'}`}
                  style={{ fontSize: 9 }}>
                  {s.status}
                </span>
              )}
            </div>
            <div className="scan-item-stats">
              {s.stats?.phase1_plan_count || 0} 方案 / {s.stats?.phase1_executed || 0} 执行
            </div>
            {onCompareScans && (
              <button
                className="chip"
                style={{ marginTop: 4, fontSize: 10 }}
                onClick={(e) => { e.stopPropagation(); onCompareScans(s.scan_id); }}
              >
                {selectedIds?.includes(s.scan_id) ? '取消对比' : '选择对比'}
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
