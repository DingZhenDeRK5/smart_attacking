import { API_BASE } from './helpers';

const PROVIDERS = [
  { id: 'deepseek', name: 'DeepSeek', models: ['deepseek-chat', 'deepseek-reasoner'] },
  { id: 'openai', name: 'OpenAI', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4.1'] },
  { id: 'anthropic', name: 'Anthropic Claude', models: ['claude-sonnet-4-20250514', 'claude-haiku-4-5-20251001', 'claude-opus-4-8'] },
  { id: 'custom', name: '自定义 (OpenAI 兼容)', models: [] },
];

export default function ModelSelector({ provider, model, customBaseUrl, customModel, onChange, disabled }) {
  const selectedProvider = PROVIDERS.find((p) => p.id === provider) || PROVIDERS[0];

  function handleProviderChange(e) {
    const newProvider = e.target.value;
    const p = PROVIDERS.find((pp) => pp.id === newProvider);
    onChange({
      provider: newProvider,
      model: p && p.models.length > 0 ? p.models[0] : model,
      customBaseUrl: newProvider === 'custom' ? customBaseUrl : '',
      customModel: newProvider === 'custom' ? '' : '',
    });
  }

  return (
    <div className="model-select-group">
      <label className="control-label">AI 模型</label>
      <select className="model-select" value={provider} onChange={handleProviderChange} disabled={disabled}>
        {PROVIDERS.map((p) => (
          <option key={p.id} value={p.id}>{p.name}</option>
        ))}
      </select>

      {selectedProvider.models.length > 0 && (
        <select
          className="model-select"
          value={model}
          onChange={(e) => onChange({ provider, model: e.target.value, customBaseUrl, customModel })}
          disabled={disabled}
          style={{ marginTop: 6 }}
        >
          {selectedProvider.models.map((m) => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
      )}

      {provider === 'custom' && (
        <>
          <input
            type="text"
            className="model-select-input"
            placeholder="Base URL (e.g., http://localhost:11434/v1)"
            value={customBaseUrl}
            onChange={(e) => onChange({ provider, model, customBaseUrl: e.target.value, customModel })}
            disabled={disabled}
            style={{ marginTop: 6 }}
          />
          <input
            type="text"
            className="model-select-input"
            placeholder="Model name (e.g., llama3)"
            value={customModel}
            onChange={(e) => onChange({ provider, model, customBaseUrl, customModel: e.target.value })}
            disabled={disabled}
            style={{ marginTop: 6 }}
          />
        </>
      )}
    </div>
  );
}
