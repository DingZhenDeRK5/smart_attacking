import { useState } from 'react';

export default function ResultCard({ icon, iconClass, title, subtitle, badge, badgeClass, defaultOpen, children }) {
  const [open, setOpen] = useState(defaultOpen ?? true);
  return (
    <div className="result-card">
      <div className="result-card-header" onClick={() => setOpen((v) => !v)}>
        <div className="card-title-group">
          <div className={`card-icon ${iconClass}`}>{icon}</div>
          <div>
            <div className="card-title">{title}</div>
            {subtitle && <div className="card-subtitle">{subtitle}</div>}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {badge && <span className={`card-badge ${badgeClass}`}>{badge}</span>}
          <span className={`card-chevron ${open ? 'open' : ''}`}>▼</span>
        </div>
      </div>
      <div className={`result-card-body ${open ? 'open' : ''}`}>{children}</div>
    </div>
  );
}
