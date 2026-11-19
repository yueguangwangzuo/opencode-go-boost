# opencode-go-boost

**让 opencode go 变快。** 从 Cloudflare 边缘里挑最快的那条路给 `opencode.ai/inference/go`，并且把「链路慢」和「模型慢」分开量——不是换个壳的 best-ip。

同时是 dsh-go 手机 App 的原生插件（胶囊 / 状态条 / 面板）和 Harness Web 的设置页插件。

它解决的是同一件事的两半：**链路慢** 和 **模型慢** 经常被混成一个「速度」。这个插件先把两者拆开量，再决定要不要换 IP。

- 输入框上方状态条：`HKG 362ms · …139.104`
- 胶囊「换最快IP」：重测候选，固定最快的那个
- 胶囊「全链路」：逐段拆首字节（DNS / TCP / TLS / 跨区 / 网关 / 模型）
- 面板「模型测速」：手动发 3 条真实请求，量 TTFT 与 tok/s
- 面板「链路排名」：候选 IP × 首字节 × 边缘 colo
- 网页端「设置 → 边缘 IP 优选」：同一份引擎，状态 / 排名 / 全链路 / 测速
- 给 Bot 一个 `edge_ip` 工具（`status` / `test` / `chain` / `speed3` …）

## 和 dsh-best-ip 有什么不一样

`dsh-best-ip` 是按 pi-ai 适配器写死的：它只认 `llm` 那套 provider 配置。而这台机器的默认路由常常是第三方适配器 `dsh-opencode-go`，在那套解析里会直接判成 `UNSUPPORTED_ADAPTER`，测速不可用。

| | dsh-best-ip | 本插件 |
|---|---|---|
| 适配器 | 只认 pi-ai | 三级回退：引擎当前选择 → profile `cordis.patch.yml` → 常量；第三方适配器也能定位端点 |
| 量的东西 | 首字节为主 | 首字节 **与** tok/s 分开量，附 TTFT、后端 placement、波动率 |
| 换 IP 的决策 | 快就切 | 先判「是链路慢还是模型慢」；自动模式新 IP 需快 25% 且连续 2 轮 |
| 生效方式 | 改 DNS / hosts | 进程内劫持 `dns.lookup`，只对目标域名生效，卸载即还原 |
| 密钥来源 | 自家配置 | `CUSTOM_OPENCODE_API_KEY` / `OPENCODE_GO_API_KEY` / 适配器按账号生成的 `DSH_OPENCODE_GO_ACCOUNT_*` / `.credentials.yaml` |

两者可以共存：本插件会读 `dsh-best-ip` 的候选列表当额外输入（只读，读不到就算了）。

## 装之前

- dsh-go 手机 App（原生胶囊 / 状态条 / 面板），或 Harness Web（设置页）。
- 默认模型路由走 `opencode.ai`（这是硬编码的目标域，见 `lib/index.js` 的 `HOST`）。换别的网关要改常量。
- 选「全链路」全检 / 「模型测速」时会真的发请求：单轮约 200 token，3 轮约 600 token。

## 安装

```sh
git clone https://github.com/yueguangwangzuo/opencode-go-boost.git
dsh plugin --profile web add ./dsh-edge-ip
```

装完在 App 的「引擎」页重启引擎（网页端刷新页面）。装上即生效，不用改 profile 的任何配置。

卸载：

```sh
dsh plugin --profile web remove local-edge-ip
```

## 口径（为什么数字长这样）

1. **换边缘 IP 修的是首字节，不是 tok/s。** 同一条 160 token 请求：HKG 112 tok/s / SJC 113.4 / SJC 104.1 / SEA 59.7；首字节 2019ms vs 4034ms。tok/s 主要由后端放置决定，只有链路烂到拖慢下发时才会跟着掉。
2. **tok/s 单次测量没有决策价值。** 同一个 IP 隔两小时：112 → 217（近 2 倍）。所以默认 3 轮取中位数，波动 > 60% 标「不稳定」，不拿它当基线。
3. **首字节 = 各段之和**，线路不通就显示 `—`，不拿 DNS 时间冒充。测速只在你点按时跑，不进快检、不进自动优选、不进启动流程。

## 实现要点

- **候选**：Cloudflare 15 个段分层采样（`lib/probe.js`）+ DNS + 当前固定 IP；`198.18/15`、内网、回环一律拒（挡掉 Clash fake-ip）。
- **筛选**：TCP 快筛 1.5s → 一条真实 `/cdn-cgi/trace` 验证「这个 zone 服不服务」（拒 10xx 平台错误与 5xx）。
- **排名**：近区 colo（HKG/TPE/NRT…）优先，其次首字节。
- **证书**：带 Authorization 的请求全部 `rejectUnauthorized: true`，开校验不影响可用性。
- **不写 /etc/hosts**：默认进程内拦截 `dns.lookup` / `dns.promises.lookup`；万一某个通道不走 Node 解析，才回退写系统 hosts，面板会说明。旧版本留下的标记块启动时清除。
- **测速只在点按时跑**，不自动烧 token。

## 文件

| 文件 | 作用 |
|---|---|
| `lib/index.js` | 面板、胶囊、状态条、优选与自愈流程 |
| `lib/probe.js` | CF 段采样、TCP 快筛、真实请求验证、colo 排名 |
| `lib/bench.js` | 流式测速（TTFT / tok/s / 抖动 / upstream）、多轮汇总 |
| `lib/resolver.js` | `dns.lookup` 拦截、可选 hosts 写入与迁移 |
| `lib/providers.js` | 找出真实端点与密钥（三级回退） |
| `lib/chain.js` | 全链路面板的数据采集（快检 / 全检） |
| `client.js` | Harness Web 设置页与 `/api/local-edge-ip/*` |
| `test/unit.mjs` | 离线单测（17 个用例，不打网络） |

## 开发

```sh
node test/unit.mjs                     # 离线单测
node /path/to/dsh/skills/dsh-go-plugin/kit/bin/check.mjs . --load   # 插件自查
```

改 `lib/` 后手机端在 App「引擎」页重启；网页端刷新页面（宿主侧改动仍需重启引擎）。

## 已知限制

- 目标域硬编码为 `opencode.ai`；换网关需改 `HOST` 与 `DEFAULTS`。
- 只在 Linux / Android proot 环境实测；回退写 hosts 需要写权限，没有时会提示。
- 不是 opencode 官方项目，也不代表 Cloudflare 的推荐方案。数字因地区、运营商、后端放置而异，别拿别人的绝对值当基线。

## License

MIT
