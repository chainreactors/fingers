# judge 复测：合约下沉 utils/jev 之后（2026-09-27）

## 结论

**当前代码在真实 Jev 上通过了 2026-09-26 验收的全部标准，并补上了当时遗留的两个问题。** 输入与[历史验收](jev-claim-acceptance-20260926.md)相同：69 份真实响应快照，682 个已标注的产品判断。模型为 jev-1.13.0，`MinConfidence` 为 0.3，0 份请求失败。

| 验收标准 | 2026-09-26 | 本次 | 结论 |
|---|---:|---:|---|
| 有标注的误报删除数（要求 ≥24） | 24 | **24** | ✅ |
| 真实命中误删 | 0 | **0** | ✅ |
| 3 个宝塔默认页上的宝塔 | 全部保留 | **全部保留**（insufficient，未删除） | ✅ |
| `varnish=1.1` | 不出现 | **不出现** | ✅ |
| 版本 正确/错误 | 36/0 | **36/0**，无依据填值 0，正确弃权 26 | ✅ |
| Ledger 前三 | git、ipeakcms、webp_server_go | **git、ipeakcms、webp_server_go** | ✅ |
| Discover，不加载 library | SearXNG、Wakapi 判 missing；IT Tools 判 insufficient | **三个都判 missing**（0.88 / 0.69 / 0.40） | ✅ 3/3 |
| Discover，加载 library | IT Tools 误报警 missing | **没有误报警**，IT Tools 判 insufficient（0.21） | ✅ |

## 本轮修正

**规则引擎输出不确定。** 同一份响应跑两次，合并结果可能不同。几处都按 map 顺序遍历：引擎之间、fingers 的候选规则、fingerprinthub 命中的模板、wappalyzer 的应用及其 header / cookie / meta 模式。同一产品有多条规则命中时，保留谁的 MatchDetail 和 Attributes 取决于遍历顺序，于是证据、发给 Jev 的请求和缓存键也随之变化。现在都改为固定顺序，Ledger 的排序和样本也固定了。

**两类格式版本不再作为候选。** 第一次真实复测中，Jev 在 4 个 GitHub Pages 页面上把 `Via: 1.1 varnish` 的 1.1 选为 varnish 的版本（置信度 0.41–0.74），在 Caddy 默认页上选了 SVG 的 `version="1.1"`（0.48）。这些都是代码能确定的事实：Via 头每一项开头是 HTTP 协议版本，SVG / XML 声明里的 version 是格式版本。现在它们和 viewport 的 `initial-scale=1.0`、IPv4 一样，在提取候选时由代码排除，没有加任何推翻 Jev 回答的逻辑。

**代码精简。** 以下改动都用确定性回归验证过：用一个按请求内容哈希回答的本地 Provider，跑完 judgeeval 全链路，重构前后 189 个 Provider 请求和全部输出逐字节一致。具体改动：
- Claim 合约移到 `utils/jev`。
- 删除重复的 Ruling 校验。
- 代码确定的事实使用固定的 `factClaim`。
- gen 改为 `New(j, name)`，删除 `ProbeWith`。
- 测试按机制重排。

## 用量

| 运行 | Provider 请求 | 缓存命中 | Claim 数 | 输入 token | 耗时 |
|---|---:|---:|---:|---:|---:|
| 加载 library，冷缓存 | 101 | 4 | 340 | 218,512 | 72 秒 |
| 修正版本候选后，加载 library | 11 | 91 | 331 | 25,726 | 17 秒 |
| 修正版本候选后，不加载 library | 0 | 101 | 314 | 0 | 9 秒 |

修正只改变了含 Via 头或 SVG 的页面的版本 Claim，其余请求全部命中缓存。

## 局限

- 样本仍是 69 页、59 个主机，`MinConfidence` 需要在更大的样本集上复核。
- IT Tools 的 Coverage 置信度低（0.40 / 0.21），文字很少的单页应用仍是 Discover 的弱项。
- Presence 中 insufficient 从 7 增至 12，都没有删除条目（`DropInsufficient=false`），不影响上表指标。

## 复现

```
go run ./cmd/judgeeval \
  -manifest .judge-data/expansion-20260926/run-07-final/manifest.json \
  -library .judge-data/expansion-20260926/run-07-final/library.yaml \
  -cache .judge-data/cache-v2 -out .judge-data/claim-v2b
```

`TYPESAFE_API_KEY` 只通过环境变量传入。去掉 `-library` 验证 Discover（输出在 `.judge-data/claim-v2b-nolib`）。`.judge-data/` 不纳入版本控制。
