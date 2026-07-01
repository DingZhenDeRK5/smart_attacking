export default function StatCard({ value, label, variant = 'accent' }) {
  return (
    <div className={`stat-card ${variant}`}>
      <div className="stat-value">{value ?? '—'}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
