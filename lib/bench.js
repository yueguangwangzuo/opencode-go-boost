// local-edge-ip / 一次真实流式请求的口径（移植自 dsh-best-ip/bench.js）
//
// TTFT：请求起点 → 第一个非空 text/reasoning delta（含网络，所以对比 IP 有意义）
// tok/s：只算「首 token → 流结束」，不含建连与等待，接近纯解码速度
// 两个数分开报，别混成一个「速度」。token 数只认服务端 usage 报的值。
//
// 本网关的两条硬约束（实测）：必须带 x-opencode-session（不带 400），
// 不能带 stream_options.include_usage（带了 400）；usage 在尾包自带。
import https from 'node:https'
import crypto from 'node:crypto'

const FAILURES = new Set(['timeout', 'aborted', 'no-token', 'no-completion', 'invalid-json', 'stream-error', 'http', 'network'])

export function classifyError(error) {
  const text = String(error || '')
  const http = /^http-(\d{3})$/.exec(text)
  if (http) return 'http-' + http[1]
  for (const name of FAILURES) if (text === name || text.startsWith(name + ':')) return name
  return 'error'
}

/**
 * 发一条钉住 IP 的流式请求。不落盘密钥、不回显响应体；
 * 失败只回分类码，避免把 provider 的报错正文（可能带回显）带进状态文件。
 */
export function measureStream({
  ip, servername, path, apiKey, model, maxTokens = 160, prompt, timeout = 45000,
  session = '', signal,
} = {}) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint()
    const now = () => Number(process.hrtime.bigint() - started) / 1e6
    let settled = false
    let request
    let response
    let timer
    let firstAt = null
    let prevAt = null
    let gapMax = 0
    let usage = null
    let sawData = false
    let buffer = ''
    const finish = (extra) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { response?.destroy() } catch {}
      try { request?.destroy() } catch {}
      const decodeMs = firstAt != null && prevAt != null ? Number(prevAt - firstAt) : null
      const outputTokens = usage && Number.isSafeInteger(usage.completion_tokens) ? usage.completion_tokens : null
      const tps = decodeMs != null && decodeMs > 0 && outputTokens
        ? Math.round((outputTokens / decodeMs) * 1000 * 10) / 10
        : null
      resolve({
        ip, ok: !extra.error, status: extra.status ?? 0,
        ttftMs: firstAt == null ? null : Math.round(firstAt),
        decodeMs: decodeMs == null ? null : Math.round(decodeMs),
        outputTokens, tps,
        gapMax: gapMax ? Math.round(gapMax) : 0,
        totalMs: Math.round(now()),
        colo: extra.colo || '', placement: extra.placement || '',
        upstreamMs: extra.upstreamMs ?? null, gatewayMs: extra.gatewayMs ?? null,
        ...(extra.error ? { error: classifyError(extra.error) } : {}),
      })
    }

    if (signal?.aborted) return finish({ error: 'aborted' })
    const body = JSON.stringify({
      model, stream: true, max_tokens: Math.max(1, Math.round(maxTokens)),
      messages: [{ role: 'user', content: prompt || '用三句话解释什么是 TCP 三次握手。' }],
    })
    const headers = {
      host: servername, 'content-type': 'application/json', accept: 'text/event-stream',
      authorization: 'Bearer ' + String(apiKey || ''), 'user-agent': 'dsh-go/local-edge-ip',
      'content-length': Buffer.byteLength(body),
      'x-opencode-session': session || 'edge-bench-' + crypto.randomUUID().slice(0, 12),
    }
    timer = setTimeout(() => finish({ error: 'timeout', status: response ? response.statusCode : 0 }), timeout)
    timer.unref?.()

    try {
      request = https.request({
        host: ip, port: 443, servername, path, method: 'POST', agent: false,
        rejectUnauthorized: true, headers,
      }, (res) => {
        response = res
        if (res.statusCode !== 200) {
          res.resume()
          const timing = serverTiming(res.headers)
          res.on('end', () => finish({
            error: 'http-' + res.statusCode, status: res.statusCode,
            colo: coloOf(res.headers), placement: placementOf(res.headers),
            upstreamMs: timing.upstream ?? null, gatewayMs: timing.gateway ?? null,
          }))
          return
        }
        res.setEncoding('utf8')
        res.on('data', (chunk) => {
          sawData = true
          buffer += chunk
          let index
          while ((index = buffer.indexOf('\n')) >= 0) {
            const line = buffer.slice(0, index).trim()
            buffer = buffer.slice(index + 1)
            if (line === '' || line.startsWith(':') || !line.startsWith('data:')) continue
            const payload = line.slice(5).trim()
            if (payload === '' || payload === '[DONE]') continue
            let json
            try { json = JSON.parse(payload) } catch { continue }
            if (json.usage) usage = json.usage
            const delta = json.choices && json.choices[0] && json.choices[0].delta
            const piece = delta ? (delta.content || delta.reasoning_content || '') : ''
            if (piece === '') continue
            const at = now()
            if (firstAt == null) firstAt = at
            if (prevAt != null) gapMax = Math.max(gapMax, at - prevAt)
            prevAt = at
          }
        })
        res.on('end', () => {
          const tail = buffer.trim()
          buffer = ''
          if (tail.startsWith('data:')) {
            const payload = tail.slice(5).trim()
            if (payload !== '' && payload !== '[DONE]') {
              try {
                const json = JSON.parse(payload)
                if (json.usage) usage = json.usage
              } catch { /* 半行忽略 */ }
            }
          }
          const timing = serverTiming(res.headers)
          const base = {
            status: res.statusCode, colo: coloOf(res.headers), placement: placementOf(res.headers),
            upstreamMs: timing.upstream ?? null, gatewayMs: timing.gateway ?? null,
          }
          if (firstAt == null) return finish({ ...base, error: sawData ? 'no-token' : 'stream-error' })
          if (!usage || !Number.isSafeInteger(usage.completion_tokens)) return finish({ ...base, error: 'no-completion' })
          finish(base)
        })
        res.on('error', () => finish({ error: 'stream-error', status: res.statusCode }))
      })
      request.on('error', (e) => finish({ error: e.code === 'ECONNRESET' ? 'network' : 'network' }))
      if (signal?.aborted) return finish({ error: 'aborted' })
      signal?.addEventListener?.('abort', () => finish({ error: 'aborted' }), { once: true })
      request.end(body)
    } catch {
      finish({ error: 'network' })
    }
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

export function placementOf(headers) {
  const value = headerValue(headers, 'cf-placement')
  return value.includes('-') ? value.split('-').pop() : value
}

export function serverTiming(headers) {
  const out = {}
  for (const part of String(headerValue(headers, 'server-timing') || '').split(',')) {
    const match = part.trim().match(/^([a-z0-9_-]+)\s*;\s*dur\s*=\s*([0-9.]+)/i)
    if (match) out[match[1].toLowerCase()] = Math.round(Number(match[2]))
  }
  return out
}

/** 可靠性门槛：低于这个数的样本只能当参考（一次测量自己就能差一倍）。 */
export const MIN_TOKENS = 32
export const MIN_DECODE_MS = 200
export const MIN_RUNS = 2
/** 波动超过这个百分比就当「后端在抖」，不拿它当基线。 */
export const MAX_SPREAD_PCT = 60

const median = (values) => {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b)
  if (sorted.length === 0) return null
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) * 10) / 20
}

/** 把多轮结果压成一行结论；单轮的波动必须如实说出来。 */
export function summarize(runs) {
  const list = Array.isArray(runs) ? runs.filter(Boolean) : []
  const ok = list.filter((run) => run.ok)
  const usable = ok.filter((run) => run.tps != null && run.outputTokens >= MIN_TOKENS && run.decodeMs >= MIN_DECODE_MS)
  const tpsList = usable.map((run) => run.tps)
  const ttftList = ok.map((run) => run.ttftMs).filter((value) => value != null)
  const spread = tpsList.length > 1
    ? Math.round(((Math.max(...tpsList) - Math.min(...tpsList)) / Math.max(1, median(tpsList))) * 100)
    : 0
  const unstable = tpsList.length > 1 && spread > MAX_SPREAD_PCT
  return {
    runs: list.length, ok: ok.length, usable: usable.length, unstable,
    medianTps: median(tpsList), minTps: tpsList.length ? Math.min(...tpsList) : null,
    maxTps: tpsList.length ? Math.max(...tpsList) : null,
    medianTtftMs: median(ttftList), spreadPct: spread,
    reliable: usable.length >= MIN_RUNS && !unstable,
    last: ok.length ? ok[ok.length - 1] : (list[0] || null),
    error: ok.length === 0 && list.length ? (list[0].error || 'error') : '',
  }
}
