import { useTheme } from './ThemeProvider';

export default function Header({ isScanning, modelInfo }) {
  const { theme, toggleTheme } = useTheme();
  return (
    <header className="app-header">
      <div className="header-left">
        <div className="header-logo">⚡</div>
        <span className="header-title">SmartAttack</span>
        <span className="header-badge">v3.1</span>
      </div>
      <div className="header-right">
        <button
          className="theme-toggle-btn"
          onClick={toggleTheme}
          title={theme === 'dark' ? '切换到亮色主题' : '切换到暗夜模式'}
        >
          {theme === 'dark' ? '☀️' : '🌙'}
        </button>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          AI: {modelInfo || 'DeepSeek'}
        </span>
        <span className={`status-dot ${isScanning ? 'scanning' : 'online'}`} />
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          {isScanning ? '扫描中…' : '就绪'}
        </span>
      </div>
    </header>
  );
}
