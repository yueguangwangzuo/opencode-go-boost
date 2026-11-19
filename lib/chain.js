// local-edge-ip / 全链路延迟体检
// 一次点按，把「手机 → 边缘 IP → Cloudflare 边缘 → 网关 → 模型」逐段拆开计时。
// 只在用户点按时运行；快检不带密钥、不消耗 token，全检发 1 次极小模型请求（约 10-20 token）。
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import dns from 'node:dns'
import tls from 'node:tls'
import https from 'node:https'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

export const HOST = 'opencode.ai'
export const MODEL = 'deepseek-v4.1-flash'
const API_PATH = '/inference/go/openai/v1/chat/completions'  // 完整路径兜底；providers.js 解析后由 setRoute 覆盖
const TRACE_PATH = '/cdn-cgi/trace'             // Cloudflare 边缘回显，无需鉴权
const HISTORY_MAX = 12
const PLUGIN_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CACHE_FILE = path.join(PLUGIN_DIR, 'chain.json')

// 单段超时（毫秒）。总预算控制在一个动作的 60 秒窗口内。
const LIMIT = { dns: 3000, dial: 8000, trace: 5000, chatHeaders: 12000, chat: 20000, budget: 48000 }

let route = { apiPath: API_PATH, model: MODEL, host: HOST }
export function setRoute(next) {
  if (!next || typeof next !== 'object') return route
  const apiPath = typeof next.apiPath === 'string' && next.apiPath.startsWith('/') ? next.apiPath : route.apiPath
  const model = typeof next.model === 'string' && next.model.trim() ? next.model.trim() : route.model
  const host = typeof next.host === 'string' && next.host.trim() ? next.host.trim().toLowerCase() : route.host
  route = { apiPath, model, host }
  return route
}
export const apiPathOf = () => route.apiPath
export const hostOf = () => route.host
export const currentRoute = () => ({ ...route })

let busy = false
export const isBusy = () => busy

function now() { return Number(process.hrtime.bigint()) / 1e6 }
function stamp() {
  const d = new Date()
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
function clockOf(iso) { return String(iso || '').slice(11, 16) }

// ---------- 缓存与历史 ----------
export function readCache() {
  try {
    const c = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'))
    return c && typeof c === 'object' ? c : {}
  } catch { return {} }
}

function writeCache(cache) {
  try { fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 1)) } catch {}
}

// ---------- 密钥（只在内存里拼 Authorization，不打印、不落盘） ----------
function loadKey() {
  // 环境变量名里的账号后缀因账号而异，按前缀扫，不写死某一个。
  const names = ['CUSTOM_OPENCODE_API_KEY', 'OPENCODE_GO_API_KEY', ...Object.keys(process.env).filter((n) => n.startsWith('DSH_OPENCODE_GO_ACCOUNT_'))]
  for (const name of names) {
    const v = String(process.env[name] || '').trim()
    if (v) return v
  }
  try {
    const raw = fs.readFileSync(path.join(os.homedir(), '.dsh', '.credentials.yaml'), 'utf8')
    const m = raw.match(/DSH_OPENCODE_GO_ACCOUNT_[A-Z0-9_]+:\s*['"]?(\S+?)['"]?\s*$/m)
    if (m) return m[1]
  } catch {}
  return ''
}

// ---------- 各段探测 ----------
function resolveA(host) {
  return new Promise((resolve) => {
    const t0 = now()
    let done = false
    const fin = (r) => { if (!done) { done = true; clearTimeout(timer); resolve({ ms: Math.round(now() - t0), ...r }) } }
    const timer = setTimeout(() => fin({ ips: [], err: 'timeout' }), LIMIT.dns)
    dns.resolve4(host, (err, ips) => fin(err ? { ips: [], err: err.code || 'error' } : { ips, err: null }))
  })
}

function lookupHost(host) {
  return new Promise((resolve) => dns.lookup(host, { family: 4 }, (err, address) => resolve(err ? '' : address)))
}

function coloOf(headers) {
  const ray = String((headers && headers['cf-ray']) || '')
  return ray.includes('-') ? ray.split('-').pop() : ''
}

function placementOf(headers) {
  const p = String((headers && headers['cf-placement']) || '')
  return p.includes('-') ? p.split('-').pop() : p
}

// Fetch 场景：同一条连接上顺序发请求，第二段才能测到「复用连接」的真实耗时。
function makeAgent(ip, onStage) {
  const agent = new https.Agent({ keepAlive: true, maxSockets: 1 })
  agent.createConnection = (opts, cb) => {
    const sock = tls.connect({
      host: route.host, port: 443, servername: route.host, rejectUnauthorized: true,
      lookup: (h, o, done) => (o && o.all ? done(null, [{ address: ip, family: 4 }]) : done(null, ip, 4)),
    })
    sock.once('connect', () => onStage('tcp', now()))
    sock.once('secureConnect', () => { sock.setTimeout(0); onStage('tls', now()) })
    sock.setTimeout(LIMIT.dial, () => {
      const err = new Error('dial-timeout')
      err.code = 'dial-timeout'
      try { sock.destroy(err) } catch {}
    })
    cb(null, sock)
  }
  return agent
}

function requestOnce(agent, { method = 'GET', path: p, headers = {}, body = null, timeoutMs }) {
  return new Promise((resolve) => {
    const t0 = now()
    let settled = false
    const fin = (r) => { if (!settled) { settled = true; resolve({ ...r, ms: Math.round(now() - t0) }) } }
    const req = https.request({
      hostname: route.host, port: 443, method, path: p, agent,
      headers: { host: route.host, 'user-agent': 'dsh-go/local-edge-ip', ...headers },
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => fin({
        ok: res.statusCode >= 200 && res.statusCode < 400,
        status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8').slice(0, 2048),
      }))
      res.on('error', (e) => fin({ ok: false, status: res.statusCode, err: e.code || 'stream-error' }))
    })
    req.setTimeout(timeoutMs, () => { try { req.destroy(new Error('timeout')) } catch {} })
    req.on('error', (e) => fin({ ok: false, err: e.code || (String(e.message) === 'timeout' ? 'timeout' : 'request-error') }))
    if (body) req.write(body)
    req.end()
  })
}

// SSE 流式请求：拿到响应头、首个 token、流内最大间隔。
function chatOnce(agent, { key, timeoutMs }) {
  return new Promise((resolve) => {
    const t0 = now()
    let settled = false
    const fin = (r) => { if (!settled) { settled = true; resolve({ ...r, totalMs: Math.round(now() - t0) }) } }
    const body = JSON.stringify({
      model: route.model, stream: true, max_tokens: 8,
      messages: [{ role: 'user', content: '1+1=' }],
    })
    const req = https.request({
      hostname: route.host, port: 443, method: 'POST', path: route.apiPath, agent,
      headers: {
        host: route.host, 'content-type': 'application/json', accept: 'text/event-stream',
        authorization: 'Bearer ' + key, 'user-agent': 'dsh-go/local-edge-ip',
        'x-opencode-session': 'edge-chain-' + crypto.randomUUID().slice(0, 12),
      },
    }, (res) => {
      const headersMs = Math.round(now() - t0)
      const out = {
        ok: res.statusCode >= 200 && res.statusCode < 400, status: res.statusCode,
        headersMs, headers: res.headers,
        colo: coloOf(res.headers), placement: placementOf(res.headers),
        serverTiming: parseServerTiming(res.headers['server-timing']),
      }
      if (!out.ok) {
        res.resume()
        res.on('end', () => fin({ ...out, err: 'http-' + res.statusCode, body: '' }))
        return
      }
      let buf = '', chunks = 0, firstAt = null, lastAt = null, gapMax = 0, usage = null
      res.setEncoding('utf8')
      res.on('data', (chunk) => {
        buf += chunk
        let i
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i).trim()
          buf = buf.slice(i + 1)
          if (!line.startsWith('data:')) continue
          const payload = line.slice(5).trim()
          if (payload === '[DONE]') continue
          let j
          try { j = JSON.parse(payload) } catch { continue }
          const at = now()
          chunks++
          if (lastAt != null) gapMax = Math.max(gapMax, at - lastAt)
          lastAt = at
          if (firstAt == null) firstAt = at
          if (j.usage) usage = j.usage
        }
      })
      res.on('end', () => fin({
        ...out, chunks, usage,
        ttftMs: firstAt == null ? null : Math.round(firstAt - t0),
        gapMax: gapMax ? Math.round(gapMax) : null,
      }))
      res.on('error', (e) => fin({ ...out, err: e.code || 'stream-error' }))
    })
    req.setTimeout(timeoutMs, () => { try { req.destroy(new Error('timeout')) } catch {} })
    req.on('error', (e) => fin({
      ok: false, headersMs: Math.round(now() - t0),
      err: String(e.message) === 'timeout' ? 'timeout' : (e.code || 'request-error'),
    }))
    req.end(body)
  })
}

function parseServerTiming(h) {
  const out = {}
  for (const part of String(h || '').split(',')) {
    const m = part.trim().match(/^([a-z0-9_-]+)\s*;\s*dur\s*=\s*([0-9.]+)/i)
    if (m) out[m[1].toLowerCase()] = Math.round(Number(m[2]))
  }
  return out
}

// ---------- 一条线路（固定 IP 或默认 DNS 解析出的 IP） ----------
async function runLane(key, ip, { full, wantChat, key2 }) {
  const lane = { key, ip, trace: null, chat: null, stages: { tcp: null, tls: null }, colo: '' }
  if (!ip) { lane.trace = { ok: false, err: 'no-ip', ms: 0 }; return lane }
  const t0 = now()
  let tcpAt = null
  let stageDone = false
  const onStage = (kind, at) => {
    if (stageDone) return
    if (kind === 'tcp') tcpAt = at
    if (kind === 'tls') {
      stageDone = true
      lane.stages.tcp = Math.round((tcpAt == null ? at : tcpAt) - t0)
      lane.stages.tls = Math.round(at - (tcpAt == null ? at : tcpAt))
    }
  }
  const agent = makeAgent(ip, onStage)
  try {
    const trace = await requestOnce(agent, { method: 'GET', path: TRACE_PATH, timeoutMs: LIMIT.trace })
    lane.trace = trace
    lane.colo = coloOf(trace.headers)
    if (full && wantChat && key2) lane.chat = await chatOnce(agent, { key: key2, timeoutMs: LIMIT.chat })
  } catch (e) {
    lane.trace = { ok: false, err: String((e && e.code) || (e && e.message) || e), ms: Math.round(now() - t0) }
  } finally {
    agent.destroy()
  }
  // trace 的 ms 是从「发起请求」量到响应头，TCP+TLS 已经在里面，不能再加一遍。
  // 失败时给 null：错误耗时不是「首字节」，报表里不能看起来像测到的值。
  lane.firstByteMs = lane.trace && lane.trace.ok && lane.trace.ms != null ? Math.round(lane.trace.ms) : null
  return lane
}

// ---------- 主流程 ----------
function segmentTone(label, ms, total) {
  const share = total ? ms / total : 0
  if (label === 'DNS') return ms > 300 ? 'warn' : 'good'
  if (label === 'TCP') return ms > 400 ? 'warn' : 'good'
  if (label === 'TLS') return ms > 300 ? 'warn' : 'good'
  if (label === '跨区') return ms > 1000 ? 'bad' : ms > 500 ? 'warn' : 'good'
  if (label === '后端') return ms > 1000 ? 'bad' : ms > 500 ? 'warn' : 'good'
  if (label === '网关') return ms > 500 ? 'bad' : ms > 200 ? 'warn' : 'good'
  if (label === '模型') return ms > 3000 ? 'bad' : ms > 1500 ? 'warn' : 'good'
  if (label === '首 token') return ms > 3000 ? 'warn' : 'good'
  if (share > 0.5) return 'warn'
  return 'good'
}

function buildWaterfall(dns, lane, full) {
  const segs = []
  if (dns && dns.ms != null) segs.push({ label: 'DNS', ms: dns.ms })
  if (!lane) return segs
  if (lane.stages.tcp != null) segs.push({ label: 'TCP', ms: lane.stages.tcp })
  if (lane.stages.tls != null) segs.push({ label: 'TLS', ms: lane.stages.tls })
  const chat = lane.chat
  if (full && chat && chat.ok) {
    const st = chat.serverTiming || {}
    const hasTiming = st.total != null || st.gateway != null || st.upstream != null
    if (!hasTiming) {
      // 网关没回 server-timing：把整段等待如实叫「后端（未拆）」，不假装成跨区往返。
      segs.push({ label: '后端', ms: Math.max(0, chat.headersMs) })
    } else {
      const server = st.total != null ? st.total : ((st.gateway || 0) + (st.upstream || 0))
      const rest = Math.max(0, chat.headersMs - server)
      segs.push({ label: '跨区', ms: rest })
      if (st.gateway != null) segs.push({ label: '网关', ms: st.gateway })
      if (st.upstream != null) segs.push({ label: '模型', ms: st.upstream })
    }
    if (chat.ttftMs != null) segs.push({ label: '首 token', ms: Math.max(0, chat.ttftMs - chat.headersMs) })
  } else if (lane.trace && lane.trace.ok) {
    segs.push({ label: '边缘', ms: Math.max(0, lane.trace.ms - (lane.stages.tcp || 0) - (lane.stages.tls || 0)) })
  }
  return segs
}

function errOf(lane) {
  if (!lane) return '未测'
  if (lane.trace && lane.trace.err) return lane.trace.err
  if (lane.chat && lane.chat.err) return lane.chat.err
  return '未知错误'
}

function diagnosisOf(r) {
  const pinned = r.lanes.find((l) => l.key === 'pinned')
  const def = r.lanes.find((l) => l.key === 'default')
  const pOk = !!(pinned && pinned.trace && pinned.trace.ok)
  const dOk = !!(def && def.trace && def.trace.ok)
  const chat = r.chat
  const ms = (v) => (v == null ? '—' : v + 'ms')
  const seg = (label) => (r.waterfall.find((s) => s.label === label) || {}).ms
  const gain = () => {
    if (!dOk || !pinned || pinned.firstByteMs == null || def.firstByteMs == null) return ''
    const ratio = def.firstByteMs / Math.max(1, pinned.firstByteMs)
    return ratio >= 1.6 ? `；固定 IP 比默认线路快 ${ratio.toFixed(1)}×（${pinned.colo || '?'} vs ${def.colo || '?'}）` : ''
  }

  if (!pOk && dOk) return { tone: 'bad', worst: 'pinned', text: `固定 IP 不可用（${errOf(pinned)}），默认线路正常。点「换 IP 再测」重新优选。` }
  if (!pOk && !dOk) return {
    tone: 'bad', worst: 'all',
    text: def ? `两条线路都不通（${errOf(pinned)}），先查手机网络或代理节点。` : `唯一线路不通（${errOf(pinned)}），先查手机网络或代理节点。`,
  }
  if (dOk && pinned.firstByteMs != null && def.firstByteMs != null && pinned.firstByteMs > def.firstByteMs * 1.6) {
    return { tone: 'warn', worst: 'pinned', text: `固定的 IP 反而更慢：${pinned.ip}（${pinned.colo || '?'}）${ms(pinned.firstByteMs)}，默认 ${def.ip}（${def.colo || '?'}）${ms(def.firstByteMs)}。建议换 IP。` }
  }
  if (chat && !chat.ok) {
    return { tone: 'bad', worst: 'model', text: `模型这一段失败了（${chat.err || ('http-' + chat.status)}）；链路本身可通，但这次体检不含模型耗时。` }
  }
  if (chat && chat.ok) {
    const timing = chat.serverTiming || {}
    if (timing.total == null && timing.gateway == null && timing.upstream == null) {
      return { tone: 'warn', worst: '', text: `这个网关没回 server-timing，跨区/网关/模型三段拆不开；只量到后端整段 ${ms(seg('后端'))}，边缘 ${chat.colo || '?'}。` }
    }
  }
  if (chat && chat.ok) {
    const cross = seg('跨区')
    if (cross != null && cross > 1000) {
      const place = chat.placement ? `后端在 ${chat.placement}` : '后端不在本区'
      return { tone: 'bad', worst: '跨区', text: `慢在边缘到后端这一段：${cross}ms 跨区往返（边缘 ${chat.colo || '?'} · ${place}）。模型本身只花 ${ms(seg('模型'))}。` }
    }
    if ((seg('网关') || 0) > 500) return { tone: 'bad', worst: '网关', text: `慢在网关排队：${ms(seg('网关'))}，请求还没到模型。` }
    if ((seg('模型') || 0) > 3000) return { tone: 'warn', worst: '模型', text: `慢在模型侧：${ms(seg('模型'))} 才出结果，网络这一段正常。` }
  }
  const tlsMs = seg('TLS') || 0
  const tcpMs = seg('TCP') || 0
  if (tlsMs - tcpMs > 300) return { tone: 'warn', worst: 'TLS', text: `TLS 握手比建连多 ${tlsMs - tcpMs}ms，像是丢包重传或被限速。` }
  if (tcpMs > 400) return { tone: 'warn', worst: 'TCP', text: `到边缘的 RTT 偏高（${tcpMs}ms），线路绕路。` }
  if (r.dns && r.dns.ms > 300) return { tone: 'warn', worst: 'DNS', text: `本地 DNS 解析慢（${r.dns.ms}ms）。` }
  if (chat && chat.ok && chat.gapMax > 2000) return { tone: 'warn', worst: '抖动', text: `流式输出抖动：最大间隔 ${chat.gapMax}ms。` }

  // 没命中特定规则时，用最慢的一段下结论，避免「面板说正常、柱子却是黄的」
  const bad = (r.segments || []).find((s) => s.tone === 'bad')
  const warn = (r.segments || []).filter((s) => s.tone === 'warn').sort((a, b) => b.ms - a.ms)[0]
  const total = r.headline || 0
  const pct = (v) => (total ? Math.round((v / total) * 100) : 0)
  if (bad) return { tone: 'bad', worst: bad.label, text: `${bad.label} 这一段最费时：${ms(bad.ms)}，占首字节 ${pct(bad.ms)}%。${gain()}` }
  if (warn) return { tone: 'warn', worst: warn.label, text: `偏慢的是「${warn.label}」：${ms(warn.ms)}，占首字节 ${pct(warn.ms)}%${gain()}` }
  const model = seg('模型')
  return { tone: 'good', worst: '', text: `各段均衡${model != null ? `：网络 ${ms(r.headline - model)}，模型 ${ms(model)}` : ''}${gain()}。` }
}

/** 只有线路真的通了才算首字节；失败时返回 null，避免用 DNS 时间冒充。 */
export function headlineOf(lane, waterfall) {
  const traceOk = !!(lane && lane.trace && lane.trace.ok)
  if (!traceOk) return null
  const sum = (waterfall || []).reduce((acc, segment) => acc + (segment.ms || 0), 0)
  return sum || null
}

export async function runChain({ full = false, pinnedIp = '' } = {}) {
  if (busy) throw new Error('busy')
  busy = true
  const startedAt = Date.now()
  try {
    const dns = await resolveA(route.host)
    const pinned = String(pinnedIp || '').trim() || await lookupHost(route.host)
    const fallback = (dns.ips || []).find((ip) => ip !== pinned) || ''
    const key = full ? loadKey() : ''
    const result = {
      mode: full ? 'full' : 'quick', at: stamp(), epoch: startedAt,
      dns, pinnedIp: pinned, hasKey: !!key, lanes: [], waterfall: [], chat: null,
    }

    const pinnedLane = await runLane('pinned', pinned, { full, wantChat: true, key2: key })
    result.lanes.push(pinnedLane)

    if (fallback) {
      const useChat = full && key && !(pinnedLane.chat && pinnedLane.chat.ok)
      const defLane = await runLane('default', fallback, { full, wantChat: useChat, key2: key })
      result.lanes.push(defLane)
    }

    const chatLane = result.lanes.find((l) => l.chat && l.chat.ok) || null
    result.chat = chatLane ? chatLane.chat : (result.lanes.map((l) => l.chat).find(Boolean) || null)

    const mainLane = (full && chatLane) || (pinnedLane.trace && pinnedLane.trace.ok ? pinnedLane : (result.lanes[1] || pinnedLane))
    result.mainLane = mainLane && mainLane.key
    result.waterfall = buildWaterfall(dns, mainLane, full && !!key)

    const chatOk = result.chat && result.chat.ok
    result.headline = headlineOf(mainLane, result.waterfall)

    const total = result.headline || 0
    result.segments = result.waterfall.map((s) => ({
      label: s.label, ms: s.ms, tone: segmentTone(s.label, s.ms, total),
    }))

    result.diagnosis = diagnosisOf(result)
    result.tone = result.diagnosis.tone
    result.degraded = full && !key ? 'no-key' : null

    // 历史
    const cache = readCache()
    const history = Array.isArray(cache.history) ? cache.history.slice(-(HISTORY_MAX - 1)) : []
    history.push({
      at: result.at, epoch: startedAt, mode: result.mode,
      headline: result.headline, firstByte: (mainLane && mainLane.firstByteMs) ?? null,
      model: (result.segments.find((s) => s.label === '模型') || {}).ms || null,
      ttft: chatOk ? result.chat.ttftMs : null,
      colo: (mainLane && mainLane.colo) || '', placement: (result.chat && result.chat.placement) || '',
      tone: result.tone, text: result.diagnosis.text.slice(0, 40),
    })
    writeCache({ lastRun: result.at, lastEpoch: startedAt, result, history })
    return result
  } finally {
    busy = false
  }
}

// ---------- 复制用报告（不含密钥、不含本地路径） ----------
export function formatReport(r) {
  if (!r) return ''
  const ms = (v) => (v == null ? '—' : `${v}ms`)
  const lines = []
  lines.push(`## 全链路体检 · ${r.at}（${r.mode === 'full' ? '全检' : '快检'}）`)
  lines.push(`- 首字节（含 DNS）：${ms(r.headline)}${r.chat && r.chat.ok ? ` · 边缘 ${r.chat.colo || '?'} · 后端 ${r.chat.placement || '?'}` : ''}`)
  lines.push(`- 分段：${(r.segments || []).map((s) => `${s.label} ${ms(s.ms)}`).join(' · ')}`)
  for (const lane of r.lanes || []) {
    lines.push(`- ${lane.key === 'pinned' ? '固定 IP' : '默认 DNS'}：${lane.ip}（${lane.colo || '?'}）首字节 ${ms(lane.firstByteMs)}${lane.trace && lane.trace.ok ? '' : ` 失败 ${errOf(lane)}`}`)
  }
  lines.push(`- 结论：${r.diagnosis ? r.diagnosis.text : '—'}`)
  return lines.join('\n')
}

export { clockOf, HISTORY_MAX }
export const __internals = { buildWaterfall, diagnosisOf, segmentTone, parseServerTiming, headlineOf }
