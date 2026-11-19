// 离线冒烟：用假 ctx 走一遍 apply → 路由 → 工具，不打网络。
process.env.DSH_HOME = '/tmp/dsh-go-check-smoke'
process.env.DSH_EDGE_HOSTS = '/tmp/dsh-edge-hosts-smoketest'
import assert from 'node:assert/strict'
import { apply } from '../lib/index.js'

const routes = new Map()
const tools = new Map()
const effects = []
const stash = { providerCache: null }

const runEffect = (fn) => {
  const dispose = fn()
  if (typeof dispose === 'function') effects.push(dispose)
  else effects.push(() => {})
}

const ctx = {
  effect(fn) { const dispose = fn(); effects.push(typeof dispose === 'function' ? dispose : () => {}) },
  get() { return undefined },
  logger: { info() {}, warn() {}, error() {} },
  inject(names, callback) {
    if (names.includes('webServer')) {
      callback({ effect(fn) { runEffect(fn) }, webServer: { register(route) { routes.set(route.path, route.handler); return () => routes.delete(route.path) } } })
    }
    if (names.includes('tools')) {
      callback({ effect(fn) { runEffect(fn) }, tools: { register(tool) { tools.set(tool.name, tool); return () => tools.delete(tool.name) } } })
    }
  },
}

apply(ctx)
assert.ok(routes.has('/api/local-edge-ip/state'), 'state route registered')
assert.ok(routes.has('/api/local-edge-ip/action'), 'action route registered')
assert.ok(tools.has('edge_ip'), 'tool registered')

function fakeReq(method, body, remote = '127.0.0.1') {
  const listeners = {}
  const req = {
    method, headers: { host: '127.0.0.1:3080' }, socket: { remoteAddress: remote },
    on(event, fn) { (listeners[event] ||= []).push(fn); return req },
    destroy() {},
  }
  setImmediate(() => {
    if (body !== undefined) (listeners.data || []).forEach((fn) => fn(Buffer.from(JSON.stringify(body))))
    ;(listeners.end || []).forEach((fn) => fn())
  })
  return req
}
function fakeRes() {
  return { status: 0, payload: '', writeHead(status) { this.status = status }, end(text) { this.payload = text } }
}
async function call(handler, req) {
  const res = fakeRes()
  await handler(req, res)
  return { status: res.status, body: JSON.parse(res.payload || '{}') }
}

const state = await call(routes.get('/api/local-edge-ip/state'), fakeReq('GET'))
assert.equal(state.status, 200)
assert.equal(state.body.ok, true)
assert.ok(state.body.value.edge, 'edge model present')
assert.ok(state.body.value.speed, 'speed model present')
assert.ok(state.body.value.chain, 'chain model present')

const forbidden = await call(routes.get('/api/local-edge-ip/state'), fakeReq('GET', undefined, '10.0.0.9'))
assert.equal(forbidden.status, 403, 'non-loopback rejected')

const off = await call(routes.get('/api/local-edge-ip/action'), fakeReq('POST', { action: 'autoOff' }))
assert.equal(off.body.ok, true)
assert.equal(off.body.value.actionOk, true)

const bad = await call(routes.get('/api/local-edge-ip/action'), fakeReq('POST', { action: 'nope' }))
assert.equal(bad.body.value.actionOk, false)

const status = await tools.get('edge_ip').execute({ action: 'status' })
assert.equal(status.ok, true)
assert.match(status.summary, /边缘 IP/)

for (const dispose of effects) {
  try { dispose() } catch {}
}
console.log('SMOKE OK', state.body.value.host, state.body.value.source)
