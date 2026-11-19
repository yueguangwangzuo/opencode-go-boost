// local-edge-ip / 找出「引擎此刻真正在用的模型端点」
//
// 不能像 dsh-best-ip 那样只认 pi-ai 适配器：这台机器的默认路由是第三方适配器
// dsh-opencode-go，它会在那套解析里被判成 UNSUPPORTED_ADAPTER，测速直接不可用。
// 所以这里三级回退：引擎服务 → profile 的 cordis.patch.yml → 常量。
// 只读，不改任何 provider 配置，也不触发 OAuth。
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export const FALLBACK = Object.freeze({
  provider: 'opencode', model: 'deepseek-v4.1-flash',
  baseURL: 'https://opencode.ai/inference/go/v1',
  apiKeyEnv: '',
})

const DEFAULTS = {
  'dsh-opencode-go': 'https://opencode.ai/inference/go/v1',
  'opencode-go': 'https://opencode.ai/inference/go/v1',
  'custom-opencode': 'https://opencode.ai/inference/go/openai/v1',
}

function text(value) { return typeof value === 'string' && value.trim() ? value.trim() : '' }

function dshHome() { return process.env.DSH_HOME || path.join(os.homedir(), '.dsh') }

function profileDirs() {
  const root = path.join(dshHome(), 'profiles')
  try {
    return fs.readdirSync(root).map((name) => path.join(root, name)).filter((dir) => {
      try { return fs.statSync(dir).isDirectory() } catch { return false }
    })
  } catch { return [] }
}

/** 只解析这份配置里我们关心的形状，不引入 yaml 依赖。 */
export function parsePatch(textValue) {
  const lines = String(textValue || '').split('\n')
  const out = { defaultProvider: '', defaultModel: '', providers: {}, plugins: {} }
  let section = null        // { kind: 'plugin'|'provider', id }
  let inProviders = false
  let providerKey = ''
  for (const raw of lines) {
    const line = raw.replace(/\t/g, '  ')
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue
    const top = /^-\s+id:\s*(\S+)\s*$/.exec(line)
    if (top) {
      section = { id: top[1] }
      inProviders = false
      providerKey = ''
      continue
    }
    if (!section) continue
    const name = /^ {2}name:\s*(\S+)\s*$/.exec(line)
    if (name) { section.name = name[1]; continue }
    if (/^ {2}config:\s*$/.test(line)) { section.config = true; continue }
    const indent = line.match(/^ */)[0].length
    if (indent <= 2) continue
    const keyValue = /^ *([A-Za-z0-9_.-]+):\s*(.*)$/.exec(line)
    if (!keyValue) continue
    const key = keyValue[1]
    const value = keyValue[2].replace(/\s+#.*$/, '').replace(/^['"]|['"]$/g, '').trim()

    if (section.id === 'agent-default-model') {
      if (key === 'provider') out.defaultProvider = value
      if (key === 'model') out.defaultModel = value
      continue
    }
    if (section.id === 'llm-pi-ai') {
      if (key === 'providers') { inProviders = true; continue }
      if (inProviders) {
        if (indent <= 6 && value === '') { providerKey = key; out.providers[providerKey] = { ...(out.providers[providerKey] || {}) }; continue }
        if (providerKey && indent >= 8) {
          const entry = out.providers[providerKey]
          if (key === 'displayName') entry.displayName = value
          if (key === 'api') entry.api = value
          if (key === 'baseURL') entry.baseURL = value
          if (key === 'apiKeyEnv') entry.apiKeyEnv = value
        }
      }
      continue
    }
    if (key === 'apiKeyEnv' || key === 'baseURL' || key === 'displayName') {
      out.plugins[section.id] = { ...(out.plugins[section.id] || {}), name: section.name || '', [key]: value }
    }
  }
  return out
}

function readPatch() {
  for (const dir of profileDirs()) {
    const file = path.join(dir, 'cordis.patch.yml')
    try {
      const parsed = parsePatch(fs.readFileSync(file, 'utf8'))
      if (parsed.defaultProvider || Object.keys(parsed.providers).length) return { file, parsed }
    } catch { /* 下一个 profile */ }
  }
  return { file: '', parsed: { defaultProvider: '', defaultModel: '', providers: {}, plugins: {} } }
}

function adapterDefaultBaseURL(providerId) {
  if (DEFAULTS[providerId]) return DEFAULTS[providerId]
  if (/opencode/i.test(providerId)) return DEFAULTS['dsh-opencode-go']
  return ''
}

function fromLegacyKeyFile(envName) {
  try {
    const raw = fs.readFileSync(path.join(dshHome(), '.credentials.yaml'), 'utf8')
    if (envName) {
      const exact = raw.match(new RegExp(envName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ":\\s*['\"]?(\\S+?)['\"]?\\s*$", 'm'))
      if (exact) return exact[1]
    }
    const any = raw.match(/DSH_OPENCODE_GO_ACCOUNT_[A-Z0-9_]+:\s*['"]?(\S+?)['"]?\s*$/m)
    return any ? any[1] : ''
  } catch { return '' }
}

const KEY_ENVS = ['CUSTOM_OPENCODE_API_KEY', 'OPENCODE_GO_API_KEY']
const ACCOUNT_PREFIX = 'DSH_OPENCODE_GO_ACCOUNT_'

/** 适配器按账号生成的变量名，前缀固定、后缀因人而异，所以按前缀扫而不是写死。 */
function accountEnvNames() {
  return Object.keys(process.env).filter((name) => name.startsWith(ACCOUNT_PREFIX))
}

export function loadApiKey(envName) {
  const names = envName ? [envName, ...KEY_ENVS, ...accountEnvNames()] : [...KEY_ENVS, ...accountEnvNames()]
  for (const name of names) {
    const value = text(process.env[name])
    if (value) return value
  }
  return fromLegacyKeyFile(envName)
}

function endpointOf(baseURL) {
  const url = new URL(baseURL)
  const root = url.pathname.replace(/\/+$/, '')
  return { host: url.hostname, path: root + '/chat/completions', baseURL }
}

/**
 * @returns {{provider, model, baseURL, host, apiPath, apiKey, apiKeyEnv, source, note}}
 */
export function resolveProvider(ctx) {
  const notes = []
  const profile = readPatch()
  const parsed = profile.parsed

  let provider = ''
  let model = ''
  try {
    const selection = ctx?.get?.('agentDefaultModel')?.currentSelection?.()
    if (selection && text(selection.provider)) {
      provider = text(selection.provider)
      model = text(selection.model)
      notes.push('selection')
    }
  } catch { /* 服务没装 */ }
  if (!provider) { provider = parsed.defaultProvider; if (provider) notes.push('profile') }
  if (!model) model = parsed.defaultModel
  if (!provider) provider = FALLBACK.provider
  if (!model) model = FALLBACK.model

  const plugin = parsed.plugins[provider] || {}
  const candidates = []
  for (const [id, entry] of Object.entries(parsed.providers)) {
    if (!entry) continue
    if (id === provider || plugin.name === id || (entry.displayName && entry.displayName === provider)) {
      if (entry.baseURL) candidates.push(entry.baseURL)
    }
  }
  if (plugin.baseURL) candidates.push(plugin.baseURL)
  const byAdapter = adapterDefaultBaseURL(provider)
  if (byAdapter) candidates.push(byAdapter)
  candidates.push(FALLBACK.baseURL)

  let endpoint = null
  for (const baseURL of candidates) {
    try { endpoint = endpointOf(baseURL); break } catch { /* 下一个 */ }
  }
  if (!endpoint) endpoint = endpointOf(FALLBACK.baseURL)

  const apiKeyEnv = text(plugin.apiKeyEnv) || text((parsed.providers[provider] || {}).apiKeyEnv) || accountEnvNames()[0] || ''
  const apiKey = loadApiKey(apiKeyEnv)
  const source = notes.includes('selection') ? 'service' : (notes.includes('profile') ? 'profile' : 'fallback')
  return {
    provider, model, baseURL: endpoint.baseURL, host: endpoint.host, apiPath: endpoint.path,
    apiKeyEnv, apiKey, source,
    note: apiKey ? '' : '没找到这个 provider 的 API Key',
  }
}
