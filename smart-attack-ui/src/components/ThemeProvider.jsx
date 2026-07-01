import { useState, useCallback, useEffect, createContext, useContext } from 'react';

const ThemeContext = createContext();

function getInitialTheme() {
  try {
    const saved = localStorage.getItem('smartattack-theme-v2');
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {}
  return 'light';
}

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(getInitialTheme);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark';
      try {
        localStorage.setItem('smartattack-theme-v2', next);
      } catch {}
      return next;
    });
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  return useContext(ThemeContext);
}
