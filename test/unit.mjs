// 离线单测：只测纯函数与不联网的分支，不装依赖、不打网络。
//   node --test test/unit.mjs
import test from 'node:test'
import assert from 'node:assert/strict'
import dns from 'node:dns'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

import {
  classifyIp, isCloudflareIp, isReservedIp, scanCandidates, sampleRange,
  intToIp, ipToInt, isServedByZone, rankAddresses, NEAR_COLOS,
} from '../lib/probe.js'
import { measureStream, summarize, serverTiming, classifyError, MIN_TOKENS, MIN_RUNS } from '../lib/bench.js'
import { install, uninstall, pin, unpin, pinnedOf, stripBlock, blockIp, writeBlock, HOSTS_FILE, migrateHosts } from '../lib/resolver.js'
import { parsePatch, resolveProvider, loadApiKey } from '../lib/providers.js'
import { edgeModel, speedModel, chainView, speedView } from '../lib/index.js'

test('IP 分类：Clash fake-ip 与内网一律挡下', () => {
  assert.equal(classifyIp('198.18.0.5'), 'reserved')
  assert.equal(classifyIp('10.1.2.3'), 'reserved')
  assert.equal(classifyIp('127.0.0.1'), 'reserved')
  assert.equal(classifyIp('192.168.1.1'), 'reserved')
  assert.equal(classifyIp('104.18.10.66'), 'cloudflare')
  assert.equal(classifyIp('172.66.139.104'), 'cloudflare')
  assert.equal(classifyIp('8.8.8.8'), 'other')
  assert.equal(classifyIp('999.1.1.1'), 'invalid')
  assert.equal(isCloudflareIp('198.18.0.5'), false)
  assert.equal(isReservedIp('198.18.0.5'), true)
})

test('CIDR 采样：跳过 .0/.255、只出 CF 段、预算守恒', () => {
  const ips = sampleRange('104.16.0.0/13', 4096)
  assert.ok(ips.length > 0)
  for (const ip of ips) {
    assert.equal(ip.endsWith('.0'), false)
    assert.equal(ip.endsWith('.255'), false)
    assert.equal(isCloudflareIp(ip), true)
  }
  const scanned = scanCandidates(40)
  assert.equal(scanned.length, 40)
  assert.equal(new Set(scanned).size, 40)
  for (const ip of scanned) assert.equal(isCloudflareIp(ip), true)
  // 覆盖面：不能全挤在一个段里
  const subnets = new Set(scanned.map((ip) => ip.split('.').slice(0, 2).join('.')))
  assert.ok(subnets.size >= 5, '候选应覆盖多个 CF 段，实际 ' + subnets.size)
})

test('环回转换稳定', () => {
  assert.equal(intToIp(ipToInt('104.18.10.66')), '104.18.10.66')
  assert.equal(ipToInt('1.2.3'), null)
})

test('isServedByZone：平台错误与 5xx 必须拒', () => {
  assert.equal(isServedByZone({ ok: true, status: 200, raw: 'colo=HKG' }), true)
  assert.equal(isServedByZone({ ok: true, status: 401, raw: '' }), true)
  assert.equal(isServedByZone({ ok: true, status: 429, raw: '' }), true)
  assert.equal(isServedByZone({ ok: true, status: 403, raw: '{"error":"nope"}' }), true)
  assert.equal(isServedByZone({ ok: true, status: 403, raw: 'error code: 1034' }), false)
  assert.equal(isServedByZone({ ok: true, status: 403, raw: '<html>Attention Required</html>' }), false)
  assert.equal(isServedByZone({ ok: true, status: 523, raw: 'error code: 523' }), false)
  assert.equal(isServedByZone({ ok: false, status: 0 }), false)
})

test('排名：近区 colo 优先，其次首字节', () => {
  const ranked = rankAddresses([
    { ip: '1.1.1.1', colo: 'SJC', firstByteMs: 300 },
    { ip: '2.2.2.2', colo: 'HKG', firstByteMs: 620 },
    { ip: '3.3.3.3', colo: 'NRT', firstByteMs: 500 },
    { ip: '4.4.4.4', colo: '', firstByteMs: 100 },
  ])
  assert.deepEqual(ranked.map((item) => item.ip), ['2.2.2.2', '3.3.3.3', '1.1.1.1', '4.4.4.4'])
  assert.ok(NEAR_COLOS.includes('HKG'))
})

test('DNS 拦截：两种签名都生效，卸载后还原', async () => {
  const native = dns.lookup
  const dispose = install()
  pin('edge.test', '172.66.139.104', 'HKG')
  const one = await new Promise((resolve) => dns.lookup('edge.test', (error, address) => resolve([error, address])))
  assert.deepEqual(one, [null, '172.66.139.104'])
  const many = await new Promise((resolve) => dns.lookup('edge.test', { all: true }, (error, list) => resolve([error, list])))
  assert.equal(many[0], null)
  assert.deepEqual(many[1], [{ address: '172.66.139.104', family: 4 }])
  const promised = await dns.promises.lookup('edge.test', { all: true })
  assert.deepEqual(promised, [{ address: '172.66.139.104', family: 4 }])
  assert.equal(pinnedOf('edge.test'), '172.66.139.104')
  unpin('edge.test')
  assert.equal(pinnedOf('edge.test'), '')
  dispose()
  assert.equal(dns.lookup, native, '卸载后必须还原原生 lookup')
})

test('resolver：数字 family 与缺失 hosts 文件', async () => {
  const dispose = install()
  pin('edge6.test', '172.66.214.50', 'HKG')
  const v4 = await new Promise((resolve) => dns.lookup('edge6.test', 4, (error, address) => resolve([error, address])))
  assert.deepEqual(v4, [null, '172.66.214.50'])
  const v6 = await dns.promises.lookup('edge6.test', { family: 6 }).then(() => 'resolved', (error) => error.code)
  assert.equal(v6, 'ENOTFOUND', 'family=6 必须放回原生解析')
  unpin('edge6.test')
  dispose()
  // hosts 路径在模块导入时就固定了，所以用子进程 + 环境变量验证「文件不存在就拒绝写」
  const child = spawnSync(process.execPath, ['-e', `
    const m = await import('${pathToFileURL(path.resolve('lib/resolver.js')).href}')
    try { m.writeBlock('1.2.3.4', 'x.test'); console.log('WROTE') }
    catch (error) { console.log('REFUSED') }
  `, '--input-type=module'], { encoding: 'utf8', env: { ...process.env, DSH_EDGE_HOSTS: path.join(os.tmpdir(), 'nope-' + Date.now(), 'hosts') } })
  assert.equal(child.stdout.trim(), 'REFUSED', 'hosts 不存在时不能造一个只有标记块的文件')
})

test('hosts 块：插入 / 幂等 / 清除 / 不动其它行', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-hosts-'))
  const file = path.join(dir, 'hosts')
  const original = '127.0.0.1 localhost\n::1 localhost\n10.0.0.9 other.test\n'
  fs.writeFileSync(file, original)
  const sandbox = path.join(dir, 'sandbox.mjs')
  assert.ok(HOSTS_FILE.length > 0)

  // 用环境变量指向临时文件，避免碰真的 /etc/hosts
  const previous = process.env.DSH_EDGE_HOSTS
  process.env.DSH_EDGE_HOSTS = file
  try {
    // 模块在导入时已固定 HOSTS_FILE，所以这里直接构造文本验证纯函数
    const block = '# >>> local-edge-ip\n172.66.139.104 edge.test\n# <<< local-edge-ip\n'
    const merged = original + block
    assert.equal(stripBlock(merged), original)
    assert.equal(blockIp(merged, 'edge.test'), '172.66.139.104')
    // 幂等：strip 两次结果一致
    assert.equal(stripBlock(stripBlock(merged) + block), original)
    // 已有同名映射时能被读到（first-match-wins 的告警依据）
    assert.equal(blockIp('172.66.139.104 edge.test\n' + block, 'edge.test'), '172.66.139.104')
  } finally {
    if (previous === undefined) delete process.env.DSH_EDGE_HOSTS
    else process.env.DSH_EDGE_HOSTS = previous
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('apiPath 是完整路径，setRoute 不会再拼一次', async () => {
  const { setRoute, apiPathOf, hostOf } = await import('../lib/chain.js')
  const info = resolveProvider(null)
  setRoute({ apiPath: info.apiPath, model: info.model, host: info.host })
  assert.ok(apiPathOf().endsWith('/chat/completions'), '实际 ' + apiPathOf())
  assert.equal(apiPathOf(), info.apiPath, 'chain 不能二次拼接 /chat/completions')
  assert.equal(apiPathOf().split('/chat/completions').length, 2, '路径里只能出现一次 /chat/completions')
  assert.equal(hostOf(), info.host)
  setRoute({ host: 'example.test' })
  assert.equal(hostOf(), 'example.test')
})

test('线路不通时首字节必须是 null，不能拿 DNS 时间冒充', async () => {
  const { __internals } = await import('../lib/chain.js')
  const dead = { key: 'pinned', ip: '1.2.3.4', trace: { ok: false, err: 'timeout', ms: 5000 }, stages: { tcp: null, tls: null } }
  const waterfall = __internals.buildWaterfall({ ms: 25 }, dead, false)
  assert.deepEqual(waterfall.map((segment) => segment.label), ['DNS'])
  assert.equal(__internals.headlineOf(dead, waterfall), null, '失败时不能给 25ms')
  const live = { key: 'pinned', ip: '1.2.3.4', trace: { ok: true, ms: 360 }, stages: { tcp: 120, tls: 110 } }
  const liveWaterfall = __internals.buildWaterfall({ ms: 20 }, live, false)
  assert.equal(__internals.headlineOf(live, liveWaterfall), 20 + 360)
})

test('网关没回 server-timing 时不编造跨区', async () => {
  const { __internals } = await import('../lib/chain.js')
  const lane = { key: 'pinned', ip: '1.2.3.4', colo: 'HKG', stages: { tcp: 100, tls: 100 }, trace: { ok: true, ms: 300 } }
  const chat = { ok: true, status: 200, headersMs: 1200, ttftMs: 1500, serverTiming: {}, colo: 'HKG', placement: 'IAD' }
  const quick = __internals.buildWaterfall({ ms: 20, ips: ['1.2.3.4'] }, lane, true)
  assert.deepEqual(quick.map((segment) => segment.label), ['DNS', 'TCP', 'TLS', '边缘'])
  const withChat = __internals.buildWaterfall({ ms: 20 }, { ...lane, chat }, true)
  assert.deepEqual(withChat.map((segment) => segment.label), ['DNS', 'TCP', 'TLS', '后端', '首 token'])
  assert.equal(withChat.find((segment) => segment.label === '后端').ms, 1200)
  const r = {
    lanes: [{ ...lane, trace: { ok: true, ms: 300 }, firstByteMs: 300 }],
    waterfall: withChat, headline: 1520, chat,
    segments: withChat.map((segment) => ({ label: segment.label, ms: segment.ms, tone: __internals.segmentTone(segment.label, segment.ms, 1520) })),
  }
  r.lanes.push({ key: 'default', ip: '5.6.7.8', colo: 'SEA', stages: { tcp: 200, tls: 200 }, trace: { ok: true, ms: 900 }, firstByteMs: 900 })
  const diagnosis = __internals.diagnosisOf(r)
  assert.equal(diagnosis.tone, 'warn')
  assert.match(diagnosis.text, /server-timing/)
  // 有 server-timing 时仍按跨区/网关/模型拆
  const timed = __internals.buildWaterfall({ ms: 20 }, { ...lane, chat: { ...chat, serverTiming: { total: 400, gateway: 20, upstream: 380 } } }, true)
  assert.deepEqual(timed.map((segment) => segment.label), ['DNS', 'TCP', 'TLS', '跨区', '网关', '模型', '首 token'])
})

test('tok/s 汇总：样本不足要标出来', () => {
  const run = (tps, tokens = 160, decode = 1000, ok = true) => ({
    ok, tps, outputTokens: tokens, decodeMs: decode, ttftMs: 900, error: ok ? undefined : 'timeout',
  })
  const one = summarize([run(120)])
  assert.equal(one.reliable, false, '单轮不可靠：一次测量自己就能差一倍')
  assert.equal(one.medianTps, 120)
  const two = summarize([run(120), run(140)])
  assert.equal(two.reliable, true, '两轮达到 MIN_RUNS 门槛')
  const unstable = summarize([run(102, 160, 1568), run(21, 160, 7547), run(44, 160, 3629)])
  assert.equal(unstable.unstable, true, '波动 184% 必须标记为不稳定')
  assert.equal(unstable.reliable, false)
  const three = summarize([run(120), run(140), run(160)])
  assert.equal(three.medianTps, 140)
  assert.equal(three.minTps, 120)
  assert.equal(three.maxTps, 160)
  assert.equal(three.spreadPct, 29)
  assert.equal(three.reliable, true)
  assert.equal(three.unstable, false)
  const short = summarize([run(200, 8, 100), run(200, 8, 100)])
  assert.equal(short.reliable, false, 'token 数不足/解码窗过短不算可靠')
  assert.equal(short.usable, 0)
  const failed = summarize([{ ok: false, error: 'http-429' }])
  assert.equal(failed.error, 'http-429')
  assert.equal(MIN_TOKENS, 32)
  assert.equal(MIN_RUNS, 2)
})

test('错误分类只回分类码，不泄漏正文', () => {
  assert.equal(classifyError('http-429'), 'http-429')
  assert.equal(classifyError('timeout'), 'timeout')
  assert.equal(classifyError('stream-error: upstream exploded key=sk-1'), 'stream-error')
  assert.equal(classifyError('ECONNRESET'), 'error')
})

test('server-timing 解析', () => {
  const timing = serverTiming({ 'server-timing': 'gateway;dur=16, upstream;dur=1075, total;dur=1091' })
  assert.deepEqual(timing, { gateway: 16, upstream: 1075, total: 1091 })
  assert.deepEqual(serverTiming({}), {})
})

const DSH_HOME = process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
const PROFILE_YML = path.join(DSH_HOME, 'profiles/web/cordis.patch.yml')
test('profile 解析：拿到 provider / baseURL / 密钥变量', { skip: !fs.existsSync(PROFILE_YML) && '这台机器上没有 web profile' }, () => {
  const yml = fs.readFileSync(PROFILE_YML, 'utf8')
  const parsed = parsePatch(yml)
  assert.equal(parsed.defaultProvider, 'dsh-opencode-go')
  assert.equal(parsed.defaultModel, 'deepseek-v4.1-flash')
  assert.ok(parsed.plugins['opencode-go'])
  assert.equal(parsed.plugins['opencode-go'].name, 'dsh-opencode-go')
  assert.ok(parsed.plugins['opencode-go'].apiKeyEnv.startsWith('DSH_OPENCODE_GO_ACCOUNT_'))
  const info = resolveProvider(null)
  assert.equal(info.host, 'opencode.ai')
  assert.equal(info.apiPath, '/inference/go/v1/chat/completions')
  assert.equal(info.model, 'deepseek-v4.1-flash')
  assert.equal(info.host, 'opencode.ai')
  assert.match(info.apiPath, /\/chat\/completions$/)
})

test('视图能画：edge / speed / chain', () => {
  const edge = edgeModel()
  assert.ok(edge.ip)
  assert.ok(Array.isArray(edge.rows))
  const speed = speedModel()
  assert.ok('hasData' in speed)
  for (const view of [chainView({ locale: 'zh-CN' }), speedView({ locale: 'en-US' })]) {
    assert.equal(view.type, 'stack')
    assert.ok(Array.isArray(view.children) && view.children.length > 0)
  }
})

test('测速请求在无密钥/无 IP 时立刻失败而不是挂住', async () => {
  const result = await measureStream({ ip: '127.0.0.1', servername: 'edge.test', path: '/x', apiKey: '', model: 'm', maxTokens: 8, timeout: 1500 })
  assert.equal(result.ok, false)
  assert.ok(result.error)
})
