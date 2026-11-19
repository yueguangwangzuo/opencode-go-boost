// ---------- 引擎半侧（与界面无关，只启动一次） ----------
// 网页版与手机端共用同一份状态和同一个 dns 钩子；这里拆出来是为了在没有 dshGo
// 服务的宿主（纯网页）里也能工作。
let engineStarted = false
function startEngine(ctx) {
  if (engineStarted) return
  engineStarted = true
  try { providerCache = resolveProvider(ctx) } catch { providerCache = null }
  const info = providerInfo()
  const host = info.host || HOST
  try { setRoute({ apiPath: info.apiPath, model: info.model, host: info.host }) } catch {}
  installResolver()
  try {
    if (!CHECK_LOAD && migrateHosts()) state.restored = '已把旧版本写进 /etc/hosts 的固定项清掉，改用进程内解析'
    saveState()
  } catch (error) {
    state.lastError = '清理旧 hosts 失败：' + String((error && error.message) || error)
  }
  if (state.pin && state.pin.ip) {
    if (isCloudflareIp(state.pin.ip)) applyPin(state.pin.ip, state.pin)
    else state.lastError = '上次固定的地址不在 Cloudflare 段内，已忽略：' + state.pin.ip
  }
  if (state.auto && !CHECK_LOAD) ensureTimers()

  // 保险丝：真发一条按域名走的请求，验证「进程内固定」确实生效；
  // 不通就退回写系统 hosts 的标记块（某个通道绕过 Node 解析时兜底）。
  if (!CHECK_LOAD && state.pin && state.pin.ip) {
    setTimeout(() => {
      let settled = false
      const settle = (ok) => {
        if (settled) return
        settled = true
        try {
          if (!ok) {
            writeBlock(state.pin.ip, host)
            state.hostsFallback = true
          } else {
            state.hostsFallback = false
          }
          saveState()
        } catch (error) {
          state.hostsFallback = false
          state.lastError = '进程内固定未生效，且回退写 hosts 失败：' + String((error && error.message) || error)
        }
      }
      const verify = https.request({ hostname: host, port: 443, path: '/cdn-cgi/trace', method: 'GET', timeout: 6000 }, (res) => {
        res.resume()
        settle(res.statusCode >= 200 && res.statusCode < 400)
      })
      verify.on('error', () => settle(false))
      verify.on('timeout', () => { try { verify.destroy() } catch {}; settle(false) })
      verify.end()
    }, 2500).unref?.()
  }

  ctx.effect?.(() => () => {
    for (const handle of [timer, netTimer, healthTimer]) if (handle) clearInterval(handle)
    timer = netTimer = healthTimer = null
    unpin(HOST)
    if (providerCache && providerCache.host) unpin(providerCache.host)
    uninstallResolver()
  })

  // 启动后后台量一次（不写盘、不发模型请求）
  if (!CHECK_LOAD) {
    setTimeout(() => {
      if (Date.now() < Number(state.backoffUntil || 0)) return
      rankOnce({ apply: !!state.auto, reason: 'boot' }).catch(() => {})
    }, 3000).unref?.()
  }
}

// local-edge-ip — 优选模型服务商的边缘 IP，并把「链路」和「模型速度」分开量。
//
// 三条原则（都是实测换来的）：
//   1. 候选不能只信 DNS：Cloudflare 段分层采样 + 一条真实请求验证这个 zone 到底服不服务。
//   2. tok/s 主要由后端放置决定，换 IP 只影响首字节；所以优选看首字节 + colo，tok/s 只当地手动诊断。
//   3. 不改 /etc/hosts：进程内劫持 dns.lookup，卸载可还原；旧版本写下的标记块启动时清掉。
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import dns from 'node:dns'
import https from 'node:https'
import net from 'node:net'
import { fileURLToPath } from 'node:url'
import { runChain, readCache, isBusy as chainBusy, formatReport, clockOf, setRoute } from './chain.js'
import { scanCandidates, inspectAll, inspectAddress, classifyIp, isCloudflareIp, rankAddresses, NEAR_COLOS } from './probe.js'
import { install as installResolver, uninstall as uninstallResolver, pin as pinHost, unpin, pinnedOf, resolveNative, migrateHosts, writeBlock } from './resolver.js'
import { measureStream, summarize, MIN_TOKENS } from './bench.js'
import { resolveProvider } from './providers.js'

export const name = 'local-edge-ip'

export const HOST = 'opencode.ai'
const PLUGIN_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const STATE_FILE = path.join(PLUGIN_DIR, 'state.json')
const INTERVAL_MS = 10 * 60 * 1000
const NET_CHECK_MS = 30 * 1000
const HEALTH_MS = 90 * 1000
const HEALTH_TIMEOUT_MS = 3000
const MAX_CANDIDATES = 28
const SWITCH_RATIO = 0.75
const MANUAL_MARGIN = 0.9      // 手动点按时，新 IP 至少要快 10% 才真的换
const STREAK_NEED = 2
const FORCE_REASONS = new Set(['action', 'panel', 'auto-on', 'chain-heal'])
const SPEED_TOKENS = 160
const SPEED_ROUNDS = 3
const SPEED_ROUND_MS = 15_000      // 单轮上限
const SPEED_BUDGET_MS = 45_000     // 三态总预算，必须小于动作窗口 58s

const CHECK_LOAD = /dsh-go-check-/.test(String(process.env.DSH_HOME || ''))

let state = loadState()
let running = null
let ctxRef = null
let timer = null
let netTimer = null
let healthTimer = null
let lastNetSig = ''
let healthFails = 0
let providerCache = null

function nowIso() { return new Date().toISOString().replace('T', ' ').slice(0, 19) }
function ms(value) { return value == null || Number.isNaN(value) ? '—' : Math.round(value) + ' ms' }
function fmtMs(value) { return value == null ? '—' : (value >= 1000 ? (value / 1000).toFixed(2) + ' s' : Math.round(value) + ' ms') }

function defaults() {
  return { schemaVersion: 2, auto: false, pin: null, results: [], lastRun: '—', lastError: '', streak: { ip: '', count: 0 }, backoffUntil: 0, failCount: 0, speed: null, restored: '', hostsFallback: false }
}

function loadState() {
  try {
    const raw = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'))
    const next = { ...defaults(), ...(raw && typeof raw === 'object' ? raw : {}) }
    if (!next.pin && raw && raw.ip) next.pin = { ip: raw.ip, colo: '', firstByteMs: raw.rtt ?? null, rtt: raw.rtt ?? null, at: raw.appliedAt || '' }
    next.results = (Array.isArray(next.results) ? next.results : []).map((item) => item && typeof item === 'object'
      ? { ip: item.ip, firstByte: item.firstByte ?? item.ms ?? null, colo: item.colo || '', rtt: item.rtt ?? item.ms ?? null }
      : null).filter(Boolean)
    if (next.speed != null && (typeof next.speed !== 'object' || Array.isArray(next.speed))) next.speed = null
    for (const legacy of ['ip', 'rtt', 'best', 'bestMs', 'appliedAt']) delete next[legacy]
    next.schemaVersion = 2
    return next
  } catch { return defaults() }
}

function saveState() {
  if (CHECK_LOAD) return        // 检查器加载宿主半侧时不该改真实状态
  try { fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 1)) } catch {}
}

function applyPin(ip, extra = {}) {
  const host = HOST
  pinHost(host, ip, extra.colo || '')
  state.pin = { ip, host, colo: extra.colo || '', firstByteMs: extra.firstByteMs ?? null, rtt: extra.rtt ?? null, at: nowIso() }
  saveState()
}

function providerInfo() {
  if (!providerCache) {
    try { providerCache = resolveProvider(ctxRef) } catch { providerCache = null }
  }
  return providerCache || { host: HOST, apiPath: '/inference/go/v1/chat/completions', model: 'deepseek-v4.1-flash', apiKey: '', provider: 'opencode', source: 'fallback', note: '' }
}

function targetHost() { return providerInfo().host || HOST }

// ---------- 候选 ----------
function candidatesFromOtherPlugin(host) {
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.dsh', 'dsh-best-ip', 'state.json'), 'utf8'))
    const out = []
    for (const entry of Object.values(raw.hosts || {})) {
      if (!entry || entry.hostname !== host) continue
      for (const candidate of entry.candidates || []) {
        if (candidate && isCloudflareIp(candidate.ip)) out.push(candidate.ip)
      }
    }
    return out
  } catch { return [] }
}

function resolveCurrent(host) {
  return new Promise((resolve) => {
    dns.resolve4(host, (err, ips) => resolve(err || !ips ? [] : ips))
  })
}

async function collectCandidates(host) {
  const seen = new Set()
  const out = []
  const push = (ip) => {
    const value = String(ip || '').trim()
    if (!value || seen.has(value)) return
    if (classifyIp(value) !== 'cloudflare') return
    seen.add(value)
    out.push(value)
  }
  push(pinnedOf(host) || (state.pin && state.pin.ip))
  for (const ip of await resolveCurrent(host)) push(ip)
  for (const ip of candidatesFromOtherPlugin(host)) push(ip)
  for (const ip of scanCandidates(MAX_CANDIDATES)) push(ip)
  return out.slice(0, MAX_CANDIDATES)
}

async function rankOnce({ apply = true, reason = 'manual' } = {}) {
  if (running) return running
  running = (async () => {
    const host = targetHost()
    const candidates = await collectCandidates(host)
    const found = await inspectAll(candidates, {
      concurrency: 16, waveSize: 16, servername: host, path: '/cdn-cgi/trace', timeout: 6000,
      inspect: inspectAddress,
    })
    const ranked = rankAddresses(found)
    state.lastRun = nowIso()
    state.reason = reason
    state.results = ranked.slice(0, 8).map((item) => ({ ip: item.ip, firstByte: item.firstByteMs ?? null, colo: item.colo || '', rtt: item.rtt ?? null }))
    const best = ranked[0] || null
    if (!best) {
      const fails = Number(state.failCount || 0) + 1
      state.failCount = fails
      state.backoffUntil = Date.now() + Math.min(60, 5 * 2 ** (fails - 1)) * 60 * 1000
      state.lastError = '所有候选都不可用（' + candidates.length + ' 个已尝试）'
      saveState()
      return { best: null, switched: false, ranked }
    }
    state.failCount = 0
    state.backoffUntil = 0

    const pinned = pinnedOf(host) || (state.pin && state.pin.ip) || ''
    const previousIp = pinned
    const nowBest = ranked.find((item) => item.ip === pinned) || null
    const better = nowBest && best.firstByteMs != null && nowBest.firstByteMs != null
      ? best.firstByteMs < nowBest.firstByteMs * SWITCH_RATIO
      : true
    const streak = state.streak && typeof state.streak === 'object' ? state.streak : { ip: '', count: 0 }
    if (better && nowBest) {
      streak.count = streak.ip === best.ip ? streak.count + 1 : 1
      streak.ip = best.ip
    } else {
      streak.count = 0
      streak.ip = ''
    }
    state.streak = streak

    const manualGain = nowBest && best.firstByteMs != null && nowBest.firstByteMs != null
      ? best.firstByteMs < nowBest.firstByteMs * MANUAL_MARGIN
      : !nowBest
    const shouldSwitch = !nowBest || streak.count >= STREAK_NEED || (FORCE_REASONS.has(reason) && manualGain)
    let switched = false
    if (apply && shouldSwitch) {
      try {
        applyPin(best.ip, best)
        state.lastError = ''
        switched = best.ip !== previousIp
      } catch (error) {
        state.lastError = '固定失败：' + String((error && error.message) || error)
      }
    } else if (nowBest) {
      state.pin = { ...(state.pin || {}), ip: nowBest.ip, colo: nowBest.colo || '', firstByteMs: nowBest.firstByteMs ?? null, rtt: nowBest.rtt ?? null }
    }
    saveState()
    return { best, own: nowBest, switched, ranked }
  })()
  try { return await running } finally { running = null }
}

function netSignature() {
  const out = []
  for (const [iface, list] of Object.entries(os.networkInterfaces())) {
    for (const item of list || []) if (!item.internal && item.family === 'IPv4') out.push(`${iface}:${item.address}`)
  }
  return out.sort().join(',')
}

function ensureTimers() {
  if (!state.auto) {
    if (timer) { clearInterval(timer); timer = null }
    if (netTimer) { clearInterval(netTimer); netTimer = null }
    if (healthTimer) { clearInterval(healthTimer); healthTimer = null }
    return
  }
  if (!timer) {
    timer = setInterval(() => {
      if (!state.auto) return
      if (Date.now() < Number(state.backoffUntil || 0)) return
      rankOnce({ apply: true, reason: 'interval' }).catch(() => {})
    }, INTERVAL_MS)
    timer.unref?.()
  }
  if (!netTimer) {
    lastNetSig = netSignature()
    netTimer = setInterval(() => {
      const sig = netSignature()
      if (sig === lastNetSig || !state.auto) return
      lastNetSig = sig
      rankOnce({ apply: true, reason: 'network-change' }).catch(() => {})
    }, NET_CHECK_MS)
    netTimer.unref?.()
  }
  if (!healthTimer) {
    healthTimer = setInterval(() => { checkHealth().catch(() => {}) }, HEALTH_MS)
    healthTimer.unref?.()
  }
}

async function checkHealth() {
  const host = targetHost()
  const ip = pinnedOf(host) || (state.pin && state.pin.ip)
  if (!ip || running) return
  const probe = await inspectAddress(ip, { servername: host, path: '/cdn-cgi/trace', timeout: HEALTH_TIMEOUT_MS })
  if (probe && !probe.rejected) {
    healthFails = 0
    if (probe.firstByteMs != null) state.pin = { ...(state.pin || {}), ip, firstByteMs: probe.firstByteMs, colo: probe.colo || (state.pin && state.pin.colo) || '' }
    saveState()
    return
  }
  healthFails++
  if (healthFails < 2) return
  healthFails = 0
  if (state.auto && Date.now() >= Number(state.backoffUntil || 0)) {
    await rankOnce({ apply: true, reason: 'unhealthy' })
  } else {
    state.lastError = '固定 IP 失联：' + ip
    saveState()
  }
}

// ---------- 模型速度（只在点按时跑） ----------
function speedSamplesOf(speed) {
  if (!speed || typeof speed !== 'object' || Array.isArray(speed)) return []
  if (Array.isArray(speed.samples)) return speed.samples
  if (Array.isArray(speed.runs)) return speed.runs
  return []
}

let speedRunning = false

async function runSpeed(rounds = SPEED_ROUNDS) {
  if (speedRunning || chainBusy() || running) return { error: 'busy' }
  speedRunning = true
  try {
    return await runSpeedInner(rounds)
  } finally {
    speedRunning = false
  }
}

async function runSpeedInner(rounds = SPEED_ROUNDS) {
  const info = providerInfo()
  if (!info.apiKey) return { error: 'no-key' }
  const host = info.host
  const ip = pinnedOf(host) || (state.pin && state.pin.ip) || (await resolveCurrent(host))[0] || ''
  if (!ip) return { error: 'no-ip' }
  const runs = []
  const deadline = Date.now() + SPEED_BUDGET_MS
  for (let index = 0; index < rounds; index++) {
    const left = deadline - Date.now()
    if (left < 3000) break
    const result = await measureStream({
      ip, servername: host, path: info.apiPath, apiKey: info.apiKey,
      model: info.model, maxTokens: SPEED_TOKENS,
      timeout: Math.min(SPEED_ROUND_MS, left),
    })
    runs.push(result)
    if (!result.ok) break
  }
  const summary = summarize(runs)
  state.speed = {
    at: nowIso(), epoch: Date.now(), model: info.model, route: info.source,
    host, ip, ...summary, samples: runs,
  }
  saveState()
  return state.speed
}

// ---------- 面板数据 ----------
export function edgeModel() {
  const host = targetHost()
  const pinned = pinnedOf(host) || (state.pin && state.pin.ip) || ''
  const auto = !!state.auto
  const firstByte = state.pin && state.pin.firstByteMs != null ? state.pin.firstByteMs : null
  const rows = (state.results || []).map((item) => [item.ip, item.firstByte != null ? String(Math.round(item.firstByte)) : '失败', item.colo || '—'])
  return {
    ip: pinned || '未固定',
    colo: (state.pin && state.pin.colo) || '—',
    firstByte: fmtMs(firstByte),
    rtt: ms(state.pin && state.pin.rtt),
    autoLabel: auto ? '已开启' : '已关闭',
    autoTone: auto ? 'good' : 'muted',
    lastRun: state.lastRun || '—',
    tone: state.lastError ? 'warn' : (pinned ? 'good' : 'muted'),
    note: state.lastError
      ? state.lastError
      : (pinned
        ? (state.hostsFallback
          ? `已固定 ${pinned}（${(state.pin && state.pin.colo) || '?'}），但进程内解析没生效，已回退到系统 hosts。`
          : `已把 ${host} 指向 ${pinned}（${(state.pin && state.pin.colo) || '?'}），进程内解析，不改系统 hosts。自动开着时换网 30 秒内重测。`)
        : '尚未固定：点「立即测速并应用」。优选只看首字节，模型 tok/s 不参与排名。'),
    rows,
  }
}

export function speedModel() {
  const speed = state.speed
  const samples = speedSamplesOf(speed)
  if (!speed || samples.length === 0) {
    return {
      hasData: false, ttft: '—', tps: '—', spread: '—', route: '—', backend: '—', edge: '—',
      tone: 'muted', caption: '还没测过',
      verdict: '点「快测（3 轮）」发 3 条 160 token 的真实请求（约 600 token）。单次测量自己就能差一倍，所以默认测 3 轮取中位数。',
      rows: [],
    }
  }
  const last = speed.last || samples[samples.length - 1] || {}
  const upstreams = samples.map((run) => run.upstreamMs).filter((value) => value != null)
  const tone = speed.error ? 'bad' : (!speed.reliable ? 'warn' : (speed.medianTps >= 100 ? 'good' : 'warn'))
  const verdict = speed.error
    ? `测速失败：${speed.error}`
    : speed.unstable
      ? `波动 ${speed.spreadPct}%（${speed.minTps}–${speed.maxTps} tok/s）${upstreams.length ? `，后端此刻在抖：upstream ${Math.min(...upstreams)}→${Math.max(...upstreams)}ms` : ''}。这时的 tok/s 不能当基线，换 IP 也压不下去。`
      : speed.reliable
        ? `中位 ${speed.medianTps} tok/s（${speed.minTps}–${speed.maxTps}，波动 ${speed.spreadPct}%），首 token ${fmtMs(speed.medianTtftMs)}；后端在 ${last.placement || '?'}。`
        : `只拿到 ${speed.usable}/${samples.length} 个可用样本，数字仅供参考：${speed.medianTps ?? '—'} tok/s。`
  return {
    hasData: true,
    ttft: fmtMs(speed.medianTtftMs),
    tps: speed.medianTps != null ? String(speed.medianTps) : '—',
    spread: speed.reliable ? `${speed.spreadPct}%` : '样本不足',
    route: `${speed.host} · ${speed.ip}`,
    backend: last.placement || '—',
    edge: last.colo || '—',
    tone,
    caption: `${speed.model} · ${clockOf(speed.at)} · ${samples.length} 轮`,
    verdict,
    rows: samples.map((run, index) => [
      '#' + (index + 1), run.ok ? fmtMs(run.ttftMs) : (run.error || '失败'),
      run.tps != null ? String(run.tps) : '—', run.outputTokens != null ? String(run.outputTokens) : '—',
      run.upstreamMs != null ? String(run.upstreamMs) : '—',
    ]),
  }
}

function toneWord(tone, en) {
  if (tone === 'good') return en ? 'OK' : '正常'
  if (tone === 'warn') return en ? 'Slow' : '偏慢'
  if (tone === 'bad') return en ? 'Bad' : '异常'
  return '—'
}

function agoText(epoch, en) {
  if (!epoch) return ''
  const seconds = Math.max(0, Math.round((Date.now() - epoch) / 1000))
  if (seconds < 60) return en ? 'just now' : '刚刚'
  if (seconds < 3600) return en ? Math.round(seconds / 60) + ' min ago' : Math.round(seconds / 60) + ' 分钟前'
  if (seconds < 86400) return en ? Math.round(seconds / 3600) + ' h ago' : Math.round(seconds / 3600) + ' 小时前'
  return en ? Math.round(seconds / 86400) + ' d ago' : Math.round(seconds / 86400) + ' 天前'
}

export function chainModel(caps) {
  const en = !!(caps && String(caps.locale || '').startsWith('en'))
  const cache = readCache()
  const result = cache.result
  if (!result) {
    return {
      hasData: false, headline: '—', headlineTone: 'muted',
      headCaption: en ? 'Not measured yet' : '还没测过',
      categories: [], values: [], chartCaption: '',
      stages: [{ label: en ? 'Status' : '状态', value: en ? 'Not measured yet' : '还没测过', tone: 'muted' }],
      tone: 'info', verdict: en ? 'Quick check reads the link only; full check sends one tiny request.' : '快检只测链路；全检多发 1 次极小请求。',
      lanes: [], history: [],
      ttft: '—', tps: '—', speedTone: 'muted', backend: '—',
    }
  }
  const segs = (result.segments || []).filter((segment) => segment.ms != null)
  const model = (segs.find((segment) => segment.label === '模型') || {}).ms
  const chat = result.chat && result.chat.ok ? result.chat : null
  const modeText = result.mode === 'full' ? (en ? 'Full' : '全检') : (en ? 'Quick' : '快检')
  const stages = segs.map((segment) => ({ label: segment.label, value: fmtMs(segment.ms), tone: segment.tone }))
  const mainLane = (result.lanes || []).find((lane) => lane.key === result.mainLane) || (result.lanes || [])[0]
  if (mainLane && mainLane.colo) stages.push({ label: en ? 'Edge colo' : '边缘节点', value: mainLane.colo, tone: 'good' })
  if (chat && chat.placement) stages.push({ label: en ? 'Backend' : '后端放置', value: chat.placement, tone: chat.placement === (mainLane && mainLane.colo) ? 'good' : 'warn' })

  const lanes = (result.lanes || []).map((lane) => ({
    title: lane.key === 'pinned' ? (en ? 'Pinned IP' : '固定 IP') : (en ? 'Default DNS' : '默认 DNS'),
    badge: lane.key === 'pinned' && lane.ip === result.pinnedIp ? (en ? 'current' : '当前') : '',
    rows: [
      [en ? 'First byte' : '首字节', lane.trace && lane.trace.ok ? fmtMs(lane.firstByteMs) : (en ? 'failed' : '失败')],
      [en ? 'Edge' : '边缘', lane.colo || '—'],
    ],
  }))
  if (lanes.length < 2) {
    lanes.push({ title: en ? 'Default DNS' : '默认 DNS', badge: '', rows: [[en ? 'State' : '状态', en ? 'no resolver IP' : '没取到解析 IP']] })
  }
  const history = (cache.history || []).slice(-5).reverse().map((item) => [
    clockOf(item.at), fmtMs(item.headline),
    item.mode === 'full' && item.model != null ? fmtMs(item.model) : '—', toneWord(item.tone, en),
  ])
  const upstream = chat && chat.serverTiming ? chat.serverTiming.upstream : null
  const ttft = chat && chat.ttftMs != null ? chat.ttftMs : null
  return {
    hasData: true,
    headline: fmtMs(result.headline), headlineTone: result.tone || 'good',
    headCaption: `${modeText} · ${clockOf(result.at)} · ${agoText(cache.lastEpoch, en)}`,
    categories: segs.map((segment) => segment.label), values: segs.map((segment) => Math.round(segment.ms)),
    chartCaption: en ? 'Each segment of this run, in ms' : '本次各段耗时（毫秒）',
    stages, tone: result.tone || 'info',
    verdict: (result.diagnosis && result.diagnosis.text) || '—',
    lanes, history,
    ttft: fmtMs(ttft), tps: '—',
    speedTone: upstream != null && upstream > 2000 ? 'warn' : 'good',
    backend: upstream != null ? `upstream ${upstream} ms` : ((chat && chat.placement) || '—'),
  }
}

export function chainView(caps) {
  const en = !!(caps && String(caps.locale || '').startsWith('en'))
  return {
    type: 'stack',
    title: en ? 'Full-chain latency' : '全链路延迟',
    children: [
      {
        type: 'row',
        children: [
          { type: 'metric', label: en ? 'First byte (incl. DNS)' : '首字节（含 DNS）', value: { $: 'data.headline' }, tone: { $: 'data.headlineTone' }, caption: { $: 'data.headCaption' } },
          { type: 'metric', label: en ? 'TTFT' : '首 token', value: { $: 'data.ttft' }, tone: { $: 'data.speedTone' }, caption: { $: 'data.backend' } },
        ],
      },
      {
        type: 'chart', kind: 'hbar',
        categories: { $: 'data.categories' },
        series: [{ name: en ? 'ms' : '毫秒', values: { $: 'data.values' } }],
        unit: 'ms', caption: { $: 'data.chartCaption' },
      },
      { type: 'keyValue', items: { $: 'data.stages' } },
      { type: 'callout', tone: { $: 'data.tone' }, text: { $: 'data.verdict' } },
      { type: 'compare', items: { $: 'data.lanes' } },
      {
        type: 'table',
        columns: en ? ['Time', 'First byte', 'Model', 'Verdict'] : ['时间', '首字节（含DNS）', '模型', '结论'],
        rows: { $: 'data.history' },
      },
      { type: 'text', tone: 'muted', text: en ? 'Model tok/s lives in its own panel; it is a backend signal, not an IP ranking input.' : '模型 tok/s 在单独面板里：它反映后端，不参与 IP 排名。' },
      {
        type: 'actions',
        items: [
          { label: en ? 'Quick check' : '快检', action: 'quick', style: 'primary', icon: 'play' },
          { label: en ? 'Full + model' : '全检（含模型）', action: 'full', icon: 'model' },
          { label: en ? 'Re-IP & test' : '换 IP 再测', action: 'heal', icon: 'refresh' },
          { label: en ? 'Copy report' : '复制报告', action: 'copy', icon: 'copy' },
        ],
      },
    ],
  }
}

export function speedView(caps) {
  const en = !!(caps && String(caps.locale || '').startsWith('en'))
  return {
    type: 'stack',
    title: en ? 'Model speed' : '模型速度',
    children: [
      {
        type: 'row',
        children: [
          { type: 'metric', label: 'tok/s', value: { $: 'data.tps' }, tone: { $: 'data.tone' }, caption: { $: 'data.caption' } },
          { type: 'metric', label: en ? 'TTFT' : '首 token', value: { $: 'data.ttft' }, caption: { $: 'data.route' } },
        ],
      },
      {
        type: 'keyValue',
        items: [
          { label: en ? 'Edge' : '边缘', value: { $: 'data.edge' } },
          { label: en ? 'Backend' : '后端', value: { $: 'data.backend' } },
          { label: en ? 'Spread' : '波动', value: { $: 'data.spread' } },
        ],
      },
      { type: 'callout', tone: { $: 'data.tone' }, text: { $: 'data.verdict' } },
      { type: 'table', columns: ['#', en ? 'TTFT' : '首 token', 'tok/s', en ? 'Tokens' : 'token 数', en ? 'Upstream' : '后端'], rows: { $: 'data.rows' } },
      { type: 'text', tone: 'muted', text: en ? 'Only runs when you tap. Three rounds by default; one run can differ 2x.' : '只在你点按时跑；默认 3 轮，单轮之间能差一倍。' },
      {
        type: 'actions',
        items: [
          { label: en ? 'Quick (3 runs)' : '快测（3 轮）', action: 'quick', style: 'primary', icon: 'play' },
          { label: en ? 'Single run' : '单轮', action: 'single', icon: 'play' },
          { label: en ? 'Copy' : '复制结果', action: 'copy', icon: 'copy' },
        ],
      },
    ],
  }
}

function speedReport() {
  const speed = state.speed
  if (!speed || typeof speed !== 'object' || Array.isArray(speed)) return ''
  const samples = speedSamplesOf(speed)
  if (samples.length === 0) return ''
  const lines = [`## 模型速度 · ${speed.at}（${speed.model}）`]
  lines.push(`- 中位：${speed.medianTps ?? '—'} tok/s（${speed.minTps ?? '—'}–${speed.maxTps ?? '—'}，波动 ${speed.spreadPct ?? '—'}%）`)
  lines.push(`- 首 token：${fmtMs(speed.medianTtftMs)} · 后端 ${(speed.last && speed.last.placement) || '—'} · 边缘 ${(speed.last && speed.last.colo) || '—'}`)
  for (const [index, run] of samples.entries()) {
    lines.push(`- #${index + 1}：${run.ok ? `${run.tps} tok/s · TTFT ${fmtMs(run.ttftMs)} · ${run.outputTokens} token` : '失败 ' + (run.error || '')}`)
  }
  return lines.join('\n')
}

export function apply(ctx) {
  ctxRef = ctx
  startEngine(ctx)
  installWebBridge(ctx)
  ctx.inject(['dshGo'], (ctx) => {
    const zh = (event) => !String((event && event.locale) || '').startsWith('en')

    const noteCaps = (caps) => {
      try {
        const surfaces = caps && Array.isArray(caps.surfaces) ? caps.surfaces.slice() : []
        const signature = JSON.stringify([caps && caps.app, caps && caps.protocol, surfaces])
        if (state.capsSig === signature) return
        state.capsSig = signature
        state.caps = { app: (caps && caps.app) || '', protocol: caps && caps.protocol, surfaces, at: nowIso() }
        saveState()
      } catch {}
    }

    // 输入框上方状态条
    ctx.dshGo.strip('edge-strip', (scope, emit, caps) => {
      noteCaps(caps)
      const tick = () => {
        const pin = state.pin
        if (!pin || !pin.ip) return emit({ icon: 'globe', text: '边缘IP 未固定', tone: 'muted' })
        const rtt = pin.firstByteMs != null ? Math.round(pin.firstByteMs) + 'ms' : ''
        const head = [pin.colo, rtt].filter(Boolean).join(' ')
        const shortIp = String(pin.ip).split('.').slice(-2).join('.')
        emit({
          icon: 'globe',
          text: (head ? `${head} · …${shortIp}` : `IP ${pin.ip}`).slice(0, 24),
          tone: state.lastError ? 'warn' : 'good',
        })
      }
      tick()
      const handle = setInterval(tick, 60_000)
      return () => clearInterval(handle)
    })

    // 快捷动作：换最快 IP / 打开全链路
    ctx.dshGo.on('edge-test', (scope, event) => ({
      pending: { label: zh(event) ? '正在测链路' : 'Testing', timeoutMs: 60_000 },
      result: async () => {
        const outcome = await rankOnce({ apply: true, reason: 'action' })
        if (!outcome.best) return { toast: zh(event) ? '所有候选都不可用' : 'No reachable IP', patch: edgeModel() }
        const best = outcome.best
        const own = outcome.own
        if (outcome.switched) {
          return { toast: (zh(event) ? `已切到 ${best.ip}（${best.firstByteMs}ms）` : `Switched to ${best.ip} (${best.firstByteMs}ms)`), patch: edgeModel() }
        }
        return {
          toast: own
            ? (zh(event) ? `当前 ${own.ip}（${own.firstByteMs}ms）已是最快，未更换` : `Keeping ${own.ip} (${own.firstByteMs}ms), already best`)
            : (zh(event) ? `已用 ${best.ip}（${best.firstByteMs}ms）` : `Using ${best.ip} (${best.firstByteMs}ms)`),
          patch: edgeModel(),
        }
      }
    }))
    ctx.dshGo.on('edge-chain', () => ({ open: 'panel:chain' }))
    ctx.dshGo.on('edge-speed-msg', () => ({ open: 'panel:speed' }))

    // 边缘 IP 面板
    ctx.dshGo.panel('edge', {
      view: (scope, caps) => {
        const en = !!(caps && String(caps.locale || '').startsWith('en'))
        return {
          type: 'stack',
          title: en ? 'Edge IP optimizer' : '边缘 IP 优选',
          children: [
            {
              type: 'row',
              children: [
                { type: 'metric', label: en ? 'Pinned IP' : '固定地址', value: { $: 'data.ip' }, caption: { $: 'data.colo' } },
                { type: 'metric', label: en ? 'First byte' : '首字节', value: { $: 'data.firstByte' }, tone: { $: 'data.tone' } },
              ],
            },
            {
              type: 'keyValue',
              items: [
                { label: en ? 'Auto' : '自动优选', value: { $: 'data.autoLabel' }, tone: { $: 'data.autoTone' } },
                { label: en ? 'TCP' : 'TCP 建连', value: { $: 'data.rtt' } },
                { label: en ? 'Last pick' : '上次优选', value: { $: 'data.lastRun' } },
              ],
            },
            { type: 'callout', tone: { $: 'data.tone' }, text: { $: 'data.note' } },
            {
              type: 'table',
              columns: [{ label: 'IP' }, { label: en ? 'First byte' : '首字节', align: 'right' }, { label: 'colo', align: 'right' }],
              rows: { $: 'data.rows' },
            },
            {
              type: 'actions',
              items: [
                { label: en ? 'Test & apply' : '立即测速并应用', action: 'apply', style: 'primary', icon: 'refresh' },
                { label: en ? 'Auto on' : '开启自动', action: 'autoOn', icon: 'play' },
                { label: en ? 'Auto off' : '关闭自动', action: 'autoOff' },
                { label: en ? 'Clear pin' : '清除固定', action: 'clear' },
              ],
            },
          ],
        }
      },
      data: (scope, emit) => {
        const push = () => emit(edgeModel())
        push()
        const handle = setInterval(push, 30_000)
        return () => clearInterval(handle)
      },
      actions: {
        openSpeed: () => ({ open: 'panel:speed' }),
        toggleAuto: () => {
          state.auto = !state.auto
          saveState()
          ensureTimers()
          if (state.auto) rankOnce({ apply: true, reason: 'auto-on' }).catch(() => {})
          return { toast: state.auto ? '自动优选已开启' : '自动优选已关闭', refresh: true }
        },
        apply: (scope, event) => ({
          pending: { label: zh(event) ? '正在测链路' : 'Testing', timeoutMs: 60_000 },
          result: async () => {
            const outcome = await rankOnce({ apply: true, reason: 'panel' })
            if (!outcome.best) return { toast: zh(event) ? '所有候选都不可用' : 'No reachable IP', patch: edgeModel() }
            const best = outcome.best
            if (!outcome.switched) {
              return {
                toast: outcome.own
                  ? (zh(event) ? `当前 ${outcome.own.ip}（${outcome.own.firstByteMs}ms）已是最快` : `Keeping ${outcome.own.ip}, already best`)
                  : (zh(event) ? `未更换：${best.ip}（${best.firstByteMs}ms）` : `Using ${best.ip}`),
                patch: edgeModel(),
              }
            }
            return { toast: zh(event) ? `已固定 ${best.ip}（${best.firstByteMs}ms）` : `Pinned ${best.ip} (${best.firstByteMs}ms)`, patch: edgeModel() }
          }
        }),
        autoOn: () => {
          state.auto = true
          saveState()
          ensureTimers()
          rankOnce({ apply: true, reason: 'auto-on' }).catch(() => {})
          return { toast: '自动优选已开启', refresh: true }
        },
        autoOff: () => {
          state.auto = false
          saveState()
          ensureTimers()
          return { toast: '自动优选已关闭', refresh: true }
        },
        clear: () => {
          try {
            unpin(HOST)
            unpin(providerInfo().host || HOST)
            writeBlock('', targetHost())
          } catch {}
          state.pin = null
          state.lastError = ''
          saveState()
          return { toast: '已取消固定，恢复系统解析', refresh: true }
        }
      }
    })

    // 全链路面板
    const chainAction = (full) => (scope, event) => ({
      pending: {
        label: full ? (zh(event) ? '全链体检（含模型）' : 'Full chain') : (zh(event) ? '全链路快检' : 'Chain check'),
        timeoutMs: 55_000,
      },
      result: async () => {
        if (chainBusy() || speedRunning) return { toast: zh(event) ? '正在测，等一下' : 'Busy, one moment' }
        try {
          const result = await runChain({ full, pinnedIp: pinnedOf(HOST) || (state.pin && state.pin.ip) })
          const word = result.tone === 'good' ? (zh(event) ? '正常' : 'OK')
            : result.tone === 'bad' ? (zh(event) ? '有问题' : 'Problem') : (zh(event) ? '偏慢' : 'Slow')
          return { toast: `${word} · ${fmtMs(result.headline)}`, patch: chainModel({ locale: event.locale }) }
        } catch {
          return { toast: zh(event) ? '测速失败，稍后再试' : 'Check failed, try again' }
        }
      },
    })

    ctx.dshGo.panel('chain', {
      view: (scope, caps) => chainView(caps),
      data: (scope, emit, caps) => {
        const push = () => emit(chainModel(caps))
        push()
        const handle = setInterval(push, 30_000)
        return () => clearInterval(handle)
      },
      actions: {
        quick: chainAction(false),
        full: chainAction(true),
        heal: (scope, event) => ({
          pending: { label: zh(event) ? '正在优选并体检' : 'Re-picking IP', timeoutMs: 55_000 },
          result: async () => {
            if (chainBusy() || speedRunning) return { toast: zh(event) ? '正在测，等一下' : 'Busy, one moment' }
            const outcome = await rankOnce({ apply: true, reason: 'chain-heal' })
            if (!outcome.best) return { toast: zh(event) ? '所有候选都不可用' : 'No reachable IP' }
            const target = outcome.switched ? outcome.best.ip : (pinnedOf(HOST) || outcome.best.ip)
            await runChain({ full: true, pinnedIp: target })
            return {
              toast: outcome.switched ? `${zh(event) ? '已换' : 'Now'} ${target}` : (zh(event) ? '已是最快，未换' : 'Already best'),
              patch: chainModel({ locale: event.locale }),
            }
          }
        }),
        copy: () => {
          const cache = readCache()
          if (!cache.result) return { toast: '还没测过，先点快检' }
          return { copy: formatReport(cache.result), toast: '报告已复制' }
        }
      }
    })

    // 模型速度面板（只在点按时发真实请求）
    ctx.dshGo.panel('speed', {
      view: (scope, caps) => speedView(caps),
      data: (scope, emit) => {
        const push = () => emit(speedModel())
        push()
        const handle = setInterval(push, 30_000)
        return () => clearInterval(handle)
      },
      actions: {
        quick: (scope, event) => ({
          pending: { label: zh(event) ? '测 3 轮（约 600 token）' : '3 runs (~600 tokens)', timeoutMs: 58_000 },
          result: async () => {
            const outcome = await runSpeed(SPEED_ROUNDS)
            if (outcome.error === 'no-key') return { toast: zh(event) ? '没找到模型密钥，先跑一次全检' : 'No API key found' }
            if (outcome.error === 'busy') return { toast: zh(event) ? '正在测，等一下' : 'Busy, one moment' }
            if (outcome.error) return { toast: zh(event) ? '测速失败：' + outcome.error : 'Speed test failed: ' + outcome.error, patch: speedModel() }
            return { toast: (zh(event) ? '中位 ' : 'Median ') + `${outcome.medianTps} tok/s`, patch: speedModel() }
          }
        }),
        single: (scope, event) => ({
          pending: { label: zh(event) ? '测 1 轮（约 200 token）' : '1 run (~200 tokens)', timeoutMs: 58_000 },
          result: async () => {
            const outcome = await runSpeed(1)
            if (outcome.error === 'no-key') return { toast: zh(event) ? '没找到模型密钥' : 'No API key found' }
            if (outcome.error) return { toast: zh(event) ? '测速失败：' + outcome.error : 'Speed test failed', patch: speedModel() }
            return { toast: `${outcome.medianTps ?? '—'} tok/s`, patch: speedModel() }
          }
        }),
        copy: () => {
          const report = speedReport()
          if (!report) return { toast: '还没测过，先点快测' }
          return { copy: report, toast: '结果已复制' }
        }
      }
    })

  })
}

// ---------- 网页版（Harness Web）接口 ----------
//
// 与手机端共用同一个 startEngine：一份状态、一个 dns 钩子、两条界面。
const BASE = '/api/local-edge-ip'

function report() {
  let cache = {}
  try { cache = readCache() } catch { /* 没测过 */ }
  const chain = chainModel({ locale: 'zh' })
  return {
    edge: edgeModel(),
    speed: speedModel(),
    chain,
    chainReport: cache.result ? formatReport(cache.result) : '',
    busy: { rank: !!running, chain: chainBusy(), speed: speedRunning },
    host: targetHost(),
    source: providerInfo().source,
    at: nowIso(),
  }
}

async function runAction(action) {
  switch (action) {
    case 'test': {
      const outcome = await rankOnce({ apply: true, reason: 'action' })
      if (!outcome.best) return { ok: false, message: '所有候选都不可用' }
      if (outcome.switched) return { ok: true, message: `已切到 ${outcome.best.ip}（${outcome.best.firstByteMs}ms）` }
      return { ok: true, message: outcome.own ? `当前 ${outcome.own.ip} 已是最快` : `已用 ${outcome.best.ip}（${outcome.best.firstByteMs}ms）` }
    }
    case 'autoOn':
      state.auto = true
      state.backoffUntil = 0
      saveState()
      ensureTimers()
      return { ok: true, message: '自动优选已开启（10 分钟一轮，换网 30 秒内重测）' }
    case 'autoOff':
      state.auto = false
      saveState()
      ensureTimers()
      return { ok: true, message: '自动优选已关闭，当前固定 IP 不变' }
    case 'clear': {
      const host = targetHost()
      unpin(host)
      if (providerCache && providerCache.host) unpin(providerCache.host)
      state.pin = null
      state.streak = { ip: '', count: 0 }
      state.lastError = ''
      saveState()
      return { ok: true, message: '已清除固定，恢复系统 DNS。' }
    }
    case 'chain':
    case 'chainFull': {
      if (chainBusy()) return { ok: false, message: '链路检测正在跑' }
      const result = await runChain({ full: action === 'chainFull', pinnedIp: (state.pin && state.pin.ip) || '' })
      return { ok: true, message: formatReport(result) }
    }
    case 'speed1':
    case 'speed3': {
      const outcome = await runSpeed(action === 'speed1' ? 1 : SPEED_ROUNDS)
      if (outcome.error === 'no-key') return { ok: false, message: '没找到这个 provider 的 API Key' }
      if (outcome.error === 'busy') return { ok: false, message: '正在测，等一下' }
      if (outcome.error) return { ok: false, message: '测速失败：' + outcome.error }
      return { ok: true, message: `${outcome.medianTps ?? '—'} tok/s` }
    }
    default:
      return { ok: false, message: '未知操作：' + String(action) }
  }
}

function summaryText() {
  const edge = edgeModel()
  const lines = [`边缘 IP：${edge.ip}（${edge.colo}），首字节 ${edge.firstByte}`, `自动优选：${edge.autoLabel}`, `上次优选：${edge.lastRun}`]
  if (state.lastError) lines.push(`错误：${state.lastError}`)
  const rows = (state.results || []).slice(0, 5).map((item, index) =>
    `${index + 1}. ${item.ip} ${item.firstByte != null ? Math.round(item.firstByte) + 'ms' : '失败'} ${item.colo || ''}`.trim())
  if (rows.length) lines.push('候选：', ...rows)
  return lines.join('\n')
}

/** HTTP 桥 + 给 Bot 用的 edge_ip 工具。与 dshGo 无关，纯网页宿主也能用。 */
function installWebBridge(ctx) {
  ctx.inject(['webServer'], (webCtx) => {
    webCtx.effect(() => {
      const writeJson = (res, status, body) => {
        res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' })
        res.end(JSON.stringify(body))
      }
      const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1', 'localhost'])
      const isLoopbackAddress = (address) => {
        if (typeof address !== 'string') return false
        const clean = address.startsWith('::ffff:') ? address.slice(7) : address
        return LOOPBACK.has(address) || (net.isIP(clean) === 4 && clean.startsWith('127.'))
      }
      const allowed = (req) => {
        const hostHeader = req.headers?.host
        if (typeof hostHeader !== 'string') return false
        let hostname
        try { hostname = new URL(`http://${hostHeader}`).hostname.replace(/^\[|\]$/g, '') } catch { return false }
        if (!(LOOPBACK.has(hostname) || (net.isIP(hostname) === 4 && hostname.startsWith('127.')))) return false
        return isLoopbackAddress(req.socket?.remoteAddress)
      }
      const readBody = (req) => new Promise((resolve) => {
        const chunks = []
        let size = 0
        req.on('data', (chunk) => {
          size += chunk.length
          if (size > 64 * 1024) { req.destroy(); resolve({}); return }
          chunks.push(chunk)
        })
        req.on('end', () => {
          try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')) } catch { resolve({}) }
        })
        req.on('error', () => resolve({}))
      })

      const routes = [
        {
          kind: 'exact',
          path: `${BASE}/state`,
          handler: async (req, res) => {
            if (!allowed(req)) return writeJson(res, 403, { ok: false, message: 'forbidden' })
            if (req.method !== 'GET') return writeJson(res, 405, { ok: false, message: 'method not allowed' })
            writeJson(res, 200, { ok: true, value: report() })
          },
        },
        {
          kind: 'exact',
          path: `${BASE}/action`,
          handler: async (req, res) => {
            if (!allowed(req)) return writeJson(res, 403, { ok: false, message: 'forbidden' })
            if (req.method !== 'POST') return writeJson(res, 405, { ok: false, message: 'method not allowed' })
            const body = await readBody(req)
            try {
              const outcome = await runAction(String(body?.action || ''))
              writeJson(res, 200, { ok: true, value: { message: outcome.message, actionOk: outcome.ok, state: report() } })
            } catch (error) {
              writeJson(res, 200, { ok: false, message: String((error && error.message) || error) })
            }
          },
        },
      ]
      const disposers = routes.map((route) => webCtx.webServer.register(route))
      return () => { for (const dispose of disposers) { try { dispose?.() } catch { /* 已卸载 */ } } }
    }, 'local-edge-ip: web bridge')
  })

  ctx.inject(['tools'], (toolsCtx) => {
    toolsCtx.effect(() => toolsCtx.tools.register({
      name: 'edge_ip',
      description: 'Edge-IP optimizer for the default model route: report the pinned Cloudflare edge IP and first-byte latency, or test candidates and pin the fastest.',
      parameters: {
        type: 'object',
        additionalProperties: false,
        properties: {
          action: { type: 'string', enum: ['status', 'test', 'autoOn', 'autoOff', 'clear'], description: 'status reads only; test re-measures candidates and pins the fastest; clear restores system DNS.' },
        },
        required: ['action'],
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: { ok: { type: 'boolean' }, summary: { type: 'string' } },
        },
      },
      async execute(args) {
        const action = String(args?.action || 'status')
        if (action === 'status') return { ok: true, summary: summaryText() }
        const outcome = await runAction(action)
        return { ok: outcome.ok !== false, summary: outcome.message + '\n\n' + summaryText() }
      },
    }), 'local-edge-ip: edge_ip tool')
  })
}


export { clockOf, MIN_TOKENS, NEAR_COLOS, resolveNative, classifyIp }
