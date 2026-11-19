// local-edge-ip / 网页版设置页：状态、候选排名、全链路、模型测速。
// 数据全部来自 host 的 /api/dsh-edge-ip 路由，口径与手机端面板同一份。
window.__ModuleLoader__.load({
  id: 'local-edge-ip',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useState, useEffect, useCallback } = React

    const BASE = '/api/local-edge-ip'

    const S = {
      page: { display: 'flex', flexDirection: 'column', gap: 16, padding: '4px 2px 24px', width: '100%', maxWidth: 820, minWidth: 0, boxSizing: 'border-box' },
      card: {
        minWidth: 0, boxSizing: 'border-box', border: '1px solid var(--dsw-alias-border-l1)',
        background: 'var(--dsw-alias-bg-layer-1)', borderRadius: 12, padding: 16,
        display: 'flex', flexDirection: 'column', gap: 12,
      },
      title: { fontSize: 16, fontWeight: 600, color: 'var(--dsw-alias-label-primary)', margin: 0 },
      sub: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)', margin: 0, lineHeight: 1.6 },
      row: { display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' },
      metrics: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 10 },
      metric: { padding: '10px 12px', borderRadius: 10, background: 'var(--dsw-alias-bg-base)', border: '1px solid var(--dsw-alias-border-l1)' },
      mLabel: { fontSize: 11, color: 'var(--dsw-alias-label-secondary)' },
      mValue: { fontSize: 18, fontWeight: 600, color: 'var(--dsw-alias-label-primary)', marginTop: 2 },
      btn: {
        height: 30, padding: '0 12px', borderRadius: 8, cursor: 'pointer', fontFamily: 'inherit', fontSize: 12,
        border: '1px solid var(--dsw-alias-border-l2)', background: 'var(--dsw-alias-bg-base)',
        color: 'var(--dsw-alias-label-primary)',
      },
      primary: { borderColor: 'transparent', background: 'var(--dsw-alias-brand-primary, #4d6bfe)', color: '#fff' },
      table: { width: '100%', borderCollapse: 'collapse', fontSize: 12 },
      th: { textAlign: 'left', padding: '6px 8px', color: 'var(--dsw-alias-label-secondary)', fontWeight: 500, borderBottom: '1px solid var(--dsw-alias-border-l1)' },
      td: { padding: '6px 8px', color: 'var(--dsw-alias-label-primary)', borderBottom: '1px solid var(--dsw-alias-border-l1)', fontVariantNumeric: 'tabular-nums' },
      note: { fontSize: 12, lineHeight: 1.65, color: 'var(--dsw-alias-label-secondary)', whiteSpace: 'pre-wrap' },
      bar: { height: 8, borderRadius: 4, background: 'var(--dsw-alias-brand-primary, #4d6bfe)', minWidth: 2 },
      barTrack: { flex: 1, height: 8, borderRadius: 4, background: 'var(--dsw-alias-bg-base)', overflow: 'hidden' },
      barRow: { display: 'grid', gridTemplateColumns: '76px 1fr 72px', alignItems: 'center', gap: 10, fontSize: 12 },
      mono: { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' },
      tone: { good: 'var(--dsw-alias-state-success, #12a150)', warn: 'var(--dsw-alias-state-warning, #d97706)', bad: 'var(--dsw-alias-state-error, #dc2626)', muted: 'var(--dsw-alias-label-secondary)' },
    }

    const toneColor = (tone) => S.tone[tone] || S.tone.muted

    function Metric(props) {
      return h('div', { style: S.metric },
        h('div', { style: S.mLabel }, props.label),
        h('div', { style: { ...S.mValue, color: props.tone ? toneColor(props.tone) : S.mValue.color } }, props.value),
        props.caption ? h('div', { style: S.mLabel }, props.caption) : null,
      )
    }

    function Table(props) {
      if (!props.rows || props.rows.length === 0) return h('div', { style: S.note }, props.empty || '暂无数据')
      return h('table', { style: S.table },
        h('thead', null, h('tr', null, props.columns.map((c) => h('th', { key: c, style: S.th }, c)))),
        h('tbody', null, props.rows.map((row, index) =>
          h('tr', { key: index }, row.map((cell, cellIndex) => h('td', { key: cellIndex, style: S.td }, String(cell ?? '—')))))),
      )
    }

    function Panel() {
      const [data, setData] = useState(null)
      const [error, setError] = useState('')
      const [busy, setBusy] = useState('')
      const [toast, setToast] = useState('')

      const load = useCallback(async () => {
        try {
          const response = await fetch(`${BASE}/state`, { credentials: 'same-origin' })
          const body = await response.json()
          if (body?.ok) { setData(body.value); setError('') }
          else setError(body?.message || '读取状态失败')
        } catch (cause) {
          setError(String(cause?.message || cause))
        }
      }, [])

      useEffect(() => {
        load()
        const handle = setInterval(() => { if (!document.hidden) load() }, 4000)
        return () => clearInterval(handle)
      }, [load])

      const act = useCallback(async (action) => {
        setBusy(action)
        setToast('')
        try {
          const response = await fetch(`${BASE}/action`, {
            method: 'POST', credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action }),
          })
          const body = await response.json()
          if (body?.ok) {
            setData(body.value.state)
            setToast((body.value.actionOk === false ? '✗ ' : '✓ ') + String(body.value.message || '').split('\n')[0])
          } else setToast('✗ ' + (body?.message || '操作失败'))
        } catch (cause) {
          setToast('✗ ' + String(cause?.message || cause))
        } finally {
          setBusy('')
          load()
        }
      }, [load])

      const edge = data?.edge
      const chain = data?.chain
      const speed = data?.speed
      const running = data?.busy || {}
      const disabled = (name) => busy !== '' || running.rank || running.chain || running.speed

      const stages = chain?.stages || []
      const maxStage = Math.max(1, ...((chain?.values || []).length ? chain.values : [1]))

      return h('div', { style: S.page },
        h('div', { style: S.card },
          h('div', null,
            h('h3', { style: S.title }, '边缘 IP 优选'),
            h('p', { style: S.sub }, `把默认模型路由（${data?.host || '—'}）的 Cloudflare 边缘地址实测优选并固定。只改这个进程的解析，不写系统 hosts；按答案口径只看首字节，tok/s 不参与排名。`),
          ),
          error ? h('div', { style: { ...S.note, color: toneColor('bad') } }, '读取失败：' + error) : null,
          h('div', { style: S.metrics },
            h(Metric, { label: '固定地址', value: edge?.ip || '—', caption: edge?.colo && edge.colo !== '—' ? edge.colo : '' }),
            h(Metric, { label: '首字节', value: edge?.firstByte || '—', tone: edge?.tone }),
            h(Metric, { label: '自动优选', value: edge?.autoLabel || '—', tone: edge?.autoTone }),
            h(Metric, { label: '上次优选', value: edge?.lastRun || '—' }),
          ),
          edge?.note ? h('div', { style: S.note }, edge.note) : null,
          h('div', { style: S.row },
            h('button', { style: { ...S.btn, ...S.primary }, disabled: disabled('test'), onClick: () => act('test') }, busy === 'test' || running.rank ? '测速中…' : '立即测速并应用'),
            h('button', { style: S.btn, disabled: !!busy, onClick: () => act('autoOn') }, '开启自动'),
            h('button', { style: S.btn, disabled: !!busy, onClick: () => act('autoOff') }, '关闭自动'),
            h('button', { style: S.btn, disabled: !!busy, onClick: () => act('clear') }, '清除固定'),
            h('button', { style: S.btn, disabled: !!busy, onClick: () => load() }, '刷新'),
          ),
          toast ? h('div', { style: { ...S.note, color: toast.startsWith('✓') ? toneColor('good') : toneColor('bad') } }, toast) : null,
        ),

        h('div', { style: S.card },
          h('h3', { style: S.title }, '链路排名'),
          h('p', { style: S.sub }, '本轮候选 IP 的首字节与边缘 colo。近区节点（HKG/TPE/NRT…）优先，其次看首字节。'),
          h(Table, { columns: ['IP', '首字节', 'colo'], rows: edge?.rows || [], empty: '还没测过：点「立即测速并应用」。' }),
        ),

        h('div', { style: S.card },
          h('div', { style: { ...S.row, justifyContent: 'space-between' } },
            h('h3', { style: S.title }, '全链路延迟'),
            h('div', { style: S.row },
              h('button', { style: S.btn, disabled: !!busy || running.chain, onClick: () => act('chain') }, running.chain ? '检测中…' : '快检'),
              h('button', { style: S.btn, disabled: !!busy || running.chain, onClick: () => act('chainFull') }, '全检'),
            ),
          ),
          chain?.hasData
            ? h('div', null,
                h('div', { style: S.metrics },
                  h(Metric, { label: '首字节（含 DNS）', value: chain.headline, tone: chain.headlineTone, caption: chain.headCaption }),
                  h(Metric, { label: '首 token', value: chain.ttft, tone: chain.speedTone, caption: chain.backend }),
                ),
                h('div', { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
                  stages.map((stage, index) => h('div', { key: index, style: S.barRow },
                    h('span', { style: { color: 'var(--dsw-alias-label-secondary)' } }, stage.label),
                    h('div', { style: S.barTrack },
                      h('div', {
                        style: { ...S.bar, width: `${Math.max(2, Math.round(((chain.values?.[index] || 0) / maxStage) * 100))}%`, background: toneColor(stage.tone) },
                      })),
                    h('span', { style: { textAlign: 'right', fontVariantNumeric: 'tabular-nums' } }, stage.value),
                  )),
                ),
                h('div', { style: S.note }, chain.verdict),
                (chain.lanes || []).map((lane, index) => h('div', { key: 'lane' + index },
                  h('div', { style: S.mLabel }, `${lane.title}${lane.badge ? '（' + lane.badge + '）' : ''}`),
                  h(Table, { columns: ['指标', '值'], rows: lane.rows }),
                )),
              )
            : h('div', { style: S.note }, '还没测过。快检只测链路（不消耗 token）；全检会多发 1 次极小请求。'),
        ),

        h('div', { style: S.card },
          h('div', { style: { ...S.row, justifyContent: 'space-between' } },
            h('h3', { style: S.title }, '模型速度'),
            h('div', { style: S.row },
              h('button', { style: S.btn, disabled: !!busy || running.speed, onClick: () => act('speed3') }, running.speed ? '测速中…' : '测 3 轮'),
              h('button', { style: S.btn, disabled: !!busy || running.speed, onClick: () => act('speed1') }, '测 1 轮'),
            ),
          ),
          speed?.hasData
            ? h('div', null,
                h('div', { style: S.metrics },
                  h(Metric, { label: '中位 tok/s', value: speed.tps, tone: speed.tone, caption: speed.caption }),
                  h(Metric, { label: '首 token', value: speed.ttft }),
                  h(Metric, { label: '波动', value: speed.spread }),
                  h(Metric, { label: '后端', value: speed.backend }),
                ),
                h('div', { style: S.note }, speed.verdict),
                h(Table, { columns: ['轮次', 'TTFT', 'tok/s', '输出 token', 'upstream'], rows: speed.rows }),
              )
            : h('div', { style: S.note }, '还没测过。3 轮约 600 token，单轮约 200 token；单次测量自己就能差一倍，所以默认测 3 轮取中位数。'),
        ),
      )
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('settings.section', () =>
          ctx.slots.register(
            { name: 'settings.section', id: 'local-edge-ip', order: 48, label: () => '边缘 IP 优选', inject: () => ({}) },
            Panel,
          ),
        )
      },
    }
  },
})
