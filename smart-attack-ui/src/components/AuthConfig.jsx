import { useState } from 'react';

export default function AuthConfig({ onChange, disabled }) {
  const [authType, setAuthType] = useState('none');
  const [bearerToken, setBearerToken] = useState('');
  const [apiKeyHeader, setApiKeyHeader] = useState('X-API-Key');
  const [apiKeyValue, setApiKeyValue] = useState('');
  const [basicUser, setBasicUser] = useState('');
  const [basicPass, setBasicPass] = useState('');

  function emitChange(type, config) {
    onChange?.({ type, ...config });
  }

  function handleTypeChange(e) {
    setAuthType(e.target.value);
    if (e.target.value === 'none') onChange?.({ type: 'none' });
  }

  return (
    <div className="auth-config">
      <label className="control-label">认证配置（可选）</label>
      <select className="model-select" value={authType} onChange={handleTypeChange} disabled={disabled}>
        <option value="none">无认证</option>
        <option value="bearer">Bearer Token (JWT)</option>
        <option value="api_key">API Key</option>
        <option value="basic">Basic Auth</option>
      </select>

      {authType === 'bearer' && (
        <input
          type="text" className="model-select-input" placeholder="Bearer Token…"
          value={bearerToken}
          onChange={(e) => { setBearerToken(e.target.value); emitChange('bearer', { token: e.target.value }); }}
          disabled={disabled} style={{ marginTop: 6 }}
        />
      )}
      {authType === 'api_key' && (
        <>
          <input
            type="text" className="model-select-input" placeholder="Header name (e.g., X-API-Key)"
            value={apiKeyHeader}
            onChange={(e) => { setApiKeyHeader(e.target.value); emitChange('api_key', { header: e.target.value, value: apiKeyValue }); }}
            disabled={disabled} style={{ marginTop: 6 }}
          />
          <input
            type="text" className="model-select-input" placeholder="API Key value…"
            value={apiKeyValue}
            onChange={(e) => { setApiKeyValue(e.target.value); emitChange('api_key', { header: apiKeyHeader, value: e.target.value }); }}
            disabled={disabled} style={{ marginTop: 6 }}
          />
        </>
      )}
      {authType === 'basic' && (
        <>
          <input
            type="text" className="model-select-input" placeholder="Username"
            value={basicUser}
            onChange={(e) => { setBasicUser(e.target.value); emitChange('basic', { username: e.target.value, password: basicPass }); }}
            disabled={disabled} style={{ marginTop: 6 }}
          />
          <input
            type="password" className="model-select-input" placeholder="Password"
            value={basicPass}
            onChange={(e) => { setBasicPass(e.target.value); emitChange('basic', { username: basicUser, password: e.target.value }); }}
            disabled={disabled} style={{ marginTop: 6 }}
          />
        </>
      )}
    </div>
  );
}
