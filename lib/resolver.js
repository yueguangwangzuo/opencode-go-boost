// local-edge-ip / 把选定的 IP 交给引擎，而不是交给整个系统。
//
// 做法移植自 dsh-best-ip：在进程内劫持 dns.lookup / dns.promises.lookup，
// 只对受管主机名生效，卸载时还原。好处是不写 /etc/hosts（掉电写坏全系统解析）、
// 不需要 root、回滚干净；代价是只影响本引擎进程（模型请求都在这里，够用）。
//
// 另留一个「同时写系统 hosts」开关给需要其它程序也走固定 IP 的场合，默认关；
// 旧版本写下的标记块在启动时会被清掉（migrate）。
import dns from 'node:dns'
import fs from 'node:fs'

const RUNTIME = Symbol.for('dsh.local-edge-ip.dns')
const NATIVE = (globalThis[RUNTIME] ??= {
  lookup: dns.lookup,
  promise: dns.promises.lookup,
})

export const HOSTS_FILE = process.env.DSH_EDGE_HOSTS || '/etc/hosts'
const MARK_BEGIN = '# >>> local-edge-ip'
const MARK_END = '# <<< local-edge-ip'
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

const pins = new Map()
let restore = null

export function pin(host, ip, colo = '') {
  const key = String(host || '').toLowerCase()
  if (!key || !IPV4.test(String(ip || ''))) return false
  pins.set(key, { ip: String(ip), colo: String(colo || '') })
  return true
}

export function unpin(host) {
  pins.delete(String(host || '').toLowerCase())
}

export function pinnedOf(host) {
  const hit = pins.get(String(host || '').toLowerCase())
  return hit ? hit.ip : ''
}

export function pinCount() { return pins.size }

/** 装钩子；重复调用安全，返回的 dispose 会还原原生实现。 */
export function install() {
  if (restore) return restore
  const patchedLookup = function lookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {} }
    const ip = pinnedOf(hostname)
    if (!ip || IPV4.test(String(hostname)) || IPV4.test(String(hostname).replace(/[\[\]]/g, ''))) {
      return NATIVE.lookup.call(dns, hostname, options, callback)
    }
    const family = typeof options === 'number' ? options : Number(options && options.family) || 0
    if (family && family !== 4) return NATIVE.lookup.call(dns, hostname, options, callback)
    const all = !!(options && options.all)
    process.nextTick(() => {
      try {
        if (all) callback(null, [{ address: ip, family: 4 }])
        else callback(null, ip, 4)
      } catch { /* 调用方已经走了 */ }
    })
    return {}
  }
  const patchedPromise = async function lookup(hostname, options) {
    const ip = pinnedOf(hostname)
    if (!ip || IPV4.test(String(hostname))) return NATIVE.promise.call(dns.promises, hostname, options)
    const family = typeof options === 'number' ? options : Number(options && options.family) || 0
    if (family && family !== 4) return NATIVE.promise.call(dns.promises, hostname, options)
    if (options && options.all) return [{ address: ip, family: 4 }]
    return { address: ip, family: 4 }
  }
  dns.lookup = patchedLookup
  dns.promises.lookup = patchedPromise
  restore = () => {
    if (dns.lookup === patchedLookup) dns.lookup = NATIVE.lookup
    if (dns.promises.lookup === patchedPromise) dns.promises.lookup = NATIVE.promise
    restore = null
  }
  return restore
}

export function uninstall() {
  if (restore) restore()
}

/** 绕过钩子看真实解析结果：用来判断「钉的 IP 到底生效了没有」。 */
export function resolveNative(host) {
  return new Promise((resolve) => {
    try {
      NATIVE.promise.call(dns.promises, host, { family: 4 })
        .then((value) => resolve(value && value.address ? value.address : String(value || '')))
        .catch(() => resolve(''))
    } catch { resolve('') }
  })
}

// ---------- 可选的系统 hosts 写入（默认不用） ----------

export function readHosts() {
  try { return fs.readFileSync(HOSTS_FILE, 'utf8') } catch { return '' }
}

export function stripBlock(text) {
  const out = []
  let skip = false
  for (const line of String(text || '').split('\n')) {
    if (line.trim() === MARK_BEGIN) { skip = true; continue }
    if (line.trim() === MARK_END) { skip = false; continue }
    if (!skip) out.push(line)
  }
  return out.join('\n')
}

export function blockIp(text, host) {
  const escaped = String(host).replace(/\./g, '\\.')
  const match = String(text || '').match(new RegExp(MARK_BEGIN + '\\n([^\\s]+)\\s+' + escaped))
  return match ? match[1] : ''
}

/** 原子写：先写同目录临时文件再 rename，避免掉电留下半个 /etc/hosts。 */
export function writeBlock(ip, host) {
  if (!fs.existsSync(HOSTS_FILE)) throw new Error('hosts file missing: ' + HOSTS_FILE)
  const text = stripBlock(readHosts())
  const body = ip ? `${MARK_BEGIN}\n${ip} ${host}\n${MARK_END}\n` : ''
  const next = (text === '' || text.endsWith('\n') ? text : text + '\n') + body
  const tmp = HOSTS_FILE.replace(/[^/]+$/, '.hosts.dsh-edge.tmp')
  fs.writeFileSync(tmp, next, { mode: 0o644 })
  try { fs.chmodSync(tmp, 0o644) } catch {}
  fs.renameSync(tmp, HOSTS_FILE)
  return true
}

/** 旧版本把结果写进系统 hosts；这里只负责把它清掉并报告是否清过。 */
export function migrateHosts() {
  const text = readHosts()
  if (!text.includes(MARK_BEGIN)) return false
  writeBlock('', '')
  return true
}
