// local-edge-ip / 候选 IP 探测
// 方法移植自 dsh-best-ip/probe.js（同作者授权的 MIT 思路），去掉它对 pi-ai 层的依赖：
//   候选 = Cloudflare 段分层采样（不是只信 DNS 给的两个地址）
//   筛选 = TCP 快筛（便宜）→ 一条真实 HTTP 请求（证书 + 这个 zone 到底服不服务）
//   排名 = 首字节 + 边缘 colo（近区优先），TCP 只用来淘汰死地址
// 不消耗模型 token：验证只打 /cdn-cgi/trace。
import net from 'node:net'
import https from 'node:https'

/** Cloudflare 公布的边缘段（https://www.cloudflare.com/ips-v4，2026-10 快照）。 */
export const CF_V4 = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
]

/** 离大陆近、回程通常更稳的边缘，前面的优先。只当排序先验，不代替实测。 */
export const NEAR_COLOS = ['HKG', 'TPE', 'NRT', 'KIX', 'ICN', 'SIN', 'BKK', 'MNL', 'SGN', 'SZX', 'CAN', 'PVG']

const RESERVED = ['10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15', '100.64.0.0/10']

export function ipToInt(ip) {
  const parts = String(ip).split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const part of parts) {
    const n = Number(part)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    out = ((out << 8) >>> 0) + n
  }
  return out >>> 0
}

export function intToIp(value) {
  const v = value >>> 0
  return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.')
}

function cidrOf(cidr) {
  const [base, bits] = String(cidr).split('/')
  const start = ipToInt(base)
  if (start == null) return null
  const size = 2 ** (32 - Number(bits))
  return { start, end: start + size - 1, size }
}

const ZONES = [...CF_V4, ...RESERVED].map((cidr) => ({ cidr, name: RESERVED.includes(cidr) ? 'reserved' : 'cloudflare', ...cidrOf(cidr) }))

/** 这个 IPv4 是不是 Cloudflare 边缘（任何保留/内网段都判否，Clash fake-ip 会被挡下）。 */
export function classifyIp(ip) {
  const value = ipToInt(ip)
  if (value == null) return 'invalid'
  for (const zone of ZONES) if (value >= zone.start && value <= zone.end) return zone.name
  return 'other'
}

export const isCloudflareIp = (ip) => classifyIp(ip) === 'cloudflare'
export const isReservedIp = (ip) => classifyIp(ip) === 'reserved'

function fnv1a(key) {
  let hash = 2166136261
  for (let i = 0; i < key.length; i++) hash = Math.imul(hash ^ key.charCodeAt(i), 16777619)
  return hash >>> 0
}

/** 在一条 CIDR 里按 stride 取样，跳过 .0/.255 两种主机形状。 */
export function sampleRange(cidr, stride) {
  const zone = cidrOf(cidr)
  if (!zone || !Number.isInteger(stride) || stride < 1) return []
  const out = []
  for (let offset = 1; offset < zone.size; offset += stride) {
    const ip = intToIp(zone.start + offset)
    if (!ip.endsWith('.0') && !ip.endsWith('.255')) out.push(ip)
  }
  return out
}

/**
 * 在 CF 的 15 个段之间均摊预算，每段用稳定盐取一个位置，再轮转合并。
 * 目的是覆盖面，不是均匀随机，也不能保证某个地址一定可用——每个都要实测。
 */
export function scanCandidates(limit = 40) {
  const budget = Math.max(1, Math.floor(Number(limit) || 0))
  const per = Math.max(1, Math.ceil(budget / CF_V4.length))
  const groups = CF_V4.map((cidr) => {
    const zone = cidrOf(cidr)
    const stride = Math.max(1, Math.floor(zone.size / per))
    const start = fnv1a(cidr) % stride
    const ips = []
    for (let k = 0; k < per; k++) {
      const offset = start + k * stride
      if (offset >= zone.size) break
      const ip = intToIp(zone.start + offset)
      if (!ip.endsWith('.0') && !ip.endsWith('.255')) ips.push(ip)
    }
    return ips
  })
  const out = []
  for (let round = 0; round < per; round++) {
    for (const group of groups) if (group[round] !== undefined) out.push(group[round])
  }
  return out.filter(isCloudflareIp).slice(0, budget)
}

/** TCP 建连耗时（ms）；失败或超时返回 null。ICMP 在 CF 边缘常被过滤，所以不用 ping。 */
export function tcpRtt(ip, { port = 443, timeout = 1500 } = {}) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint()
    let settled = false
    let socket
    const finish = (ok) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { socket?.destroy() } catch {}
      resolve(ok ? Math.round(Number(process.hrtime.bigint() - started) / 1e6) : null)
    }
    const timer = setTimeout(() => finish(false), timeout)
    timer.unref?.()
    try {
      socket = net.connect({ host: ip, port })
    } catch { return finish(false) }
    socket.once('connect', () => finish(true))
    socket.once('timeout', () => finish(false))
    socket.once('error', () => finish(false))
    socket.once('close', () => finish(false))
    socket.setTimeout(timeout)
  })
}

function headerValue(headers, name) {
  const raw = headers && headers[name]
  return Array.isArray(raw) ? raw[0] : (raw == null ? '' : String(raw))
}

export function coloOf(headers) {
  const ray = headerValue(headers, 'cf-ray')
  return ray.includes('-') ? ray.split('-').pop().toUpperCase() : ''
}

/** 这个响应能不能证明「该 zone 在这个地址上真的服务」——证书通过不代表能路由。 */
export function isServedByZone(res) {
  if (!res || res.ok !== true) return false
  const status = Number(res.status) || 0
  const raw = String(res.raw || '')
  const platform = raw.match(/error code:\s*(\d{4})/i)
  if (platform && Number(platform[1]) >= 1000 && Number(platform[1]) < 1100) return false
  if (status >= 200 && status < 400) return true
  if (status === 401 || status === 429) return true
  if (status === 403) return /\{/.test(raw)
  if (status === 404) return true
  return false
}

/**
 * 一次钉住 IP 的 HTTP 请求：host 用 IP、SNI 用域名，一条连接同时量到建连+握手+首字节。
 * `agent: false` 保证每个候选都是冷连接，比较才公平。
 */
export function requestViaIp(ip, { servername, path = '/cdn-cgi/trace', method = 'GET', headers = {}, body = null, timeout = 6000 } = {}) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint()
    let settled = false
    const elapsed = () => Math.round(Number(process.hrtime.bigint() - started) / 1e6)
    let request
    const finish = (value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { request?.destroy() } catch {}
      resolve({ ...value, ms: elapsed() })
    }
    const timer = setTimeout(() => finish({ ok: false, err: 'timeout' }), timeout)
    timer.unref?.()
    try {
      request = https.request({
        host: ip, port: 443, servername, path, method, agent: false,
        rejectUnauthorized: true,
        headers: { host: servername, 'user-agent': 'dsh-go/local-edge-ip', accept: '*/*', ...headers }
      }, (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => finish({
          ok: res.statusCode > 0,
          status: res.statusCode, headers: res.headers,
          raw: Buffer.concat(chunks).toString('utf8').slice(0, 2048),
        }))
        res.on('error', (e) => finish({ ok: false, status: res.statusCode, err: e.code || 'stream-error' }))
      })
      request.on('error', (e) => finish({ ok: false, err: e.code || 'request-error' }))
      if (body) request.write(body)
      request.end()
    } catch (e) {
      finish({ ok: false, err: e.code || 'request-error' })
    }
  })
}

/** 先 TCP 快筛，再一条真实请求验证；任何一步不通过就是 null。 */
export async function inspectAddress(ip, { servername, path = '/cdn-cgi/trace', timeout = 6000, tcpTimeout = 1500 } = {}) {
  if (!isCloudflareIp(ip)) return { ip, rejected: classifyIp(ip) }
  const rtt = await tcpRtt(ip, { timeout: tcpTimeout })
  if (rtt == null) return { ip, rejected: 'no-tcp' }
  const res = await requestViaIp(ip, { servername, path, timeout })
  if (!res.ok || !isServedByZone(res)) return { ip, rtt, rejected: res.err || `http-${res.status}` }
  return { ip, rtt, firstByteMs: res.ms, colo: coloOf(res.headers), status: res.status }
}

function nearRank(colo) {
  if (typeof colo !== 'string' || colo === '') return NEAR_COLOS.length + 1
  const index = NEAR_COLOS.indexOf(colo)
  return index === -1 ? NEAR_COLOS.length : index
}

/** 近区优先，其次首字节；没有首字节的（只有 TCP 数）排后面。 */
export function rankAddresses(entries) {
  return [...entries].sort((a, b) => {
    const byNear = nearRank(a.colo) - nearRank(b.colo)
    if (byNear !== 0) return byNear
    const av = a.firstByteMs ?? Number.POSITIVE_INFINITY
    const bv = b.firstByteMs ?? Number.POSITIVE_INFINITY
    if (av !== bv) return av - bv
    return (a.rtt ?? Number.POSITIVE_INFINITY) - (b.rtt ?? Number.POSITIVE_INFINITY)
  })
}

/**
 * 分波并发：成本取决于最慢的那个，所以够了就停，不等慢的。
 * `enough(info, found)` 返回 true 时提前结束本轮。
 */
export async function inspectAll(ips, { concurrency = 12, waveSize, enough, onProgress, inspect = inspectAddress, servername, path, timeout, signal } = {}) {
  const found = []
  const wave = Math.max(1, waveSize ?? concurrency)
  let attempted = 0
  for (let start = 0; start < ips.length; start += wave) {
    if (signal?.aborted) break
    const slice = ips.slice(start, start + wave)
    let cursor = 0
    let done = false
    const workers = Array.from({ length: Math.min(concurrency, slice.length) }, async () => {
      while (cursor < slice.length && !done && !signal?.aborted) {
        const ip = slice[cursor++]
        const info = await inspect(ip, { servername, path, timeout, signal })
        attempted++
        if (done || signal?.aborted) return
        if (info && !info.rejected) {
          found.push(info)
          if (enough && enough(info, found)) { done = true; break }
        }
        onProgress?.({ attempted, usable: found.length, total: ips.length })
      }
    })
    await Promise.all(workers)
    if (done) break
  }
  return found
}

export const __internals = { nearRank, headerValue }
