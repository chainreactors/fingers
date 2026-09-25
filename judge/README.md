# judge：指纹判定与重排层

`judge` 是 fingers 在规则引擎之上的判定（判别 + rerank）层。它不是指纹引擎：

- **召回**由规则引擎和代码负责：规则命中、在页面里按指纹名检索、从页面中抽取版本字符串；
- **判断**交给 Provider（一个模型）：只回答关于这些证据的类型化问题，例如"是否存在"、"从下面几项里选一个"；
- **决策**由代码做出：阈值、强证据保留、同名归并、结果标注。

这种分工让效果不依赖某个具体模型。[TypeSafe Jev](https://docs.typesafe.ai/api.md) 是目前唯一的 Provider（`judge/jev`）；接入 LLM、本地分类器或 reranker，只需要实现一个接口。

## 快速开始

```go
import (
    "github.com/chainreactors/fingers"
    "github.com/chainreactors/fingers/judge"
    "github.com/chainreactors/fingers/judge/jev"
)

engine, _ := fingers.NewEngine()
j, err := jev.NewJudge("")   // 读取 TYPESAFE_API_KEY；自带缓存，整个扫描共用一个
if err != nil { ... }
engine.AttachJudge(j)

frames, _ := engine.DetectContent(raw)          // 同步、离线，与之前完全相同
page, err := engine.Refine(ctx, raw, frames)    // 判定并原地标注 frames；通常异步执行
if err != nil {
    // 判定失败：frames 保持规则结果不变，照常使用即可
}
for _, f := range judge.Accepted(frames) {      // 去掉误报和同名重复之后的结果
    fmt.Println(f.Name, f.Version, judge.LayerOf(f), judge.Is(f, judge.Primary))
}
fmt.Println(page.Kind, page.Generic)            // 页面类型；是否为某个产品的标准页面
```

`Refine` 每页最多发 2 次请求：第一次判断页面和所有候选，第二次挑选版本号。命中缓存的问题不会再发。

## 能力

| 能力 | 函数 | 结果 | 实测（jev-1.13.0，1070 个真实页面） |
|---|---|---|---|
| 多引擎同名去重 | `Verify` | `Duplicate` | 重复条目 851 → 0 |
| 去误报 | `Verify` | `Rejected`；名字出现在 header/cookie 中的命中永不否决 | 否决 49% 的规则命中；仅正文出现的疑似误报 138 → 13 |
| 漏报召回 | `Verify` 的 `recall` 参数 | `Recalled`，以 `guess` 来源加入 | 新增 468 个 |
| 技术栈分层 | `Verify` | `LayerOf(f)` | — |
| 主应用 | `Verify` | `Primary`，用 `PrimaryOf(frames)` 读取 | 433 页 |
| 版本号 | `Version(r, f)` | 写入 `f.Version`（只在置信度达标、且原来没有版本号时） | 对照 generator：191 对 / 6 错 / 77 缺失（纯规则：43 / 3 / 228） |
| 页面类型 | `Classify` | `page.Kind`：`KindLogin` `KindConsole` `KindError` `KindDefault` `KindDirListing` `KindAPI` `KindContent` | 标注集 36/40 |
| 通用页面 / 新指纹候选 | `Classify` | `page.Generic`；判为通用、但没有主应用的页面就是新指纹的候选 | 标注集 38/40 |
| 规则体检 | `cmd/judgeeval` | 按引擎、按规则统计否决率 | goby 65%，fingerprinthub 55% |

做不到的：
- 认出改过品牌的产品（召回仍靠规则）；
- 凭空给出版本号（只能从代码抽取的候选里选）。

## 标注：Mark

结果直接写在 `common.Frameworks` 上，**不删除任何条目**。存储形式是 `Framework.Tags` 里的 `judge:<mark>` 和 `judge:layer=<layer>`，所以 gogo、spray 现有的输出和序列化不需要改动。读取时请用函数，不要解析 tag：

| API | 含义 |
|---|---|
| `judge.Is(f, judge.Rejected)` | 误报：不在技术栈里，或者只是正文里提到 |
| `judge.Is(f, judge.Duplicate)` | 另一个引擎对同一产品的另一种写法 |
| `judge.Is(f, judge.Primary)` | 本页所属的主应用 |
| `judge.Is(f, judge.Recalled)` | 规则漏掉、经判定确认后补入 |
| `judge.LayerOf(f)` | 所属层级：`LayerCDN` `LayerServer` `LayerRuntime` `LayerFramework` `LayerApplication` `LayerFrontend` `LayerDevice` `LayerNotPresent` |
| `judge.Judged(f)` | 是否已经判定过 |
| `judge.Accepted(frames)` | 去掉 `Rejected` 和 `Duplicate` 之后的结果 |
| `judge.PrimaryOf(frames)` | 主应用 |

`Verify` 会跳过已经判定过的条目，所以对同一份 frames 重复调用 `Refine` 不会产生额外请求。

## 缓存与去重

默认开启，不需要任何配置：

- **按问题缓存**：每个问题的缓存 key 由问题内容、具名证据、页面标题（数字归一化）和 Provider ID 组成，再加上页面签名（`Page.Signature()`：64 位 simhash；数字归一化，文本按双字切分，结构特征权重更高）。标题相同、签名相差不超过 `SimilarDistance`（默认 1）位的页面直接复用答案。问题怎么组合都能命中；部分命中时，只发送没命中的问题。
- **并发合并**：多个 worker 同时判定相似页面、问同样的问题时，只有一个请求真正发出去，其余的等它的答案。
- `Judge.Cache` 可以换成共享实现，比如 redis 或磁盘，只需要实现 `Get(key, sig)` / `Put(key, sig, value)`。设为 nil 就关闭缓存，并发合并仍然生效。
- 统计：`Judge.Requests`（实际发出的请求数）、`Judge.CacheHits`（不发请求就答完的轮次数）。

`SimilarDistance` 的取值来自实测（`cmd/judgeeval`，1070 个真实页面，32284 个答案）：复用相似页面的答案，与该页面自己的答案对比：

| 距离 ≤ | 可复用答案 | 一致率 |
|---|---|---|
| 0 | 136 | 100% |
| 1 | 159 | 100% |
| 2 | 194 | 98.5% |
| 3 | 225 | 96.9% |
| 5 | 293 | 94.9% |

所以默认值取 1，只在实测零误差的范围内复用。标题一致这个前提同样必要：没有它的话，彼此无关、特征稀疏的页面（例如中文站点，都带 `Server: nginx` 和 jquery）会出现签名距离 0–3 的碰撞。

随机抽取的互联网站点之间，能复用的答案不到 1%。收益主要在扫描场景：同一主机的大量 404 页或登录页、同一网段里的同型号设备、托管商的人机验证页。完全相同的问题，只要页面相同或相似，都会走缓存。

## 自定义问题

每项能力都是往 `Round` 里加问题的函数，调用方也可以加自己的问题，和内置问题合并在同一次请求里：

```go
page, _ := judge.NewPage(raw)
r := page.Round()
judge.Classify(r)
r.Add("honeypot", judge.Binary("Is this page a honeypot?"), func(a judge.Answer) {
    honeypot = a.Yes >= j.Threshold
})
err := r.Ask(ctx, j)
```

- 问题类型：
  - `Binary`（`Answer.Yes` 为"是"的概率，每个问题独立判断，所以一页上可以同时认定多个产品存在）；
  - `Choice`（`Answer.Choice` 和 `Confidence`，即在选项之间做 rerank）；
  - `Score`（`Answer.Score`）。
- `BinaryWith` 可以分别写明"是"和"否"的含义，判断会更准。
- `r.Evidence(name, v)` 可以把一份具名证据放进 state（例如版本号候选列表）。模型读得很字面：具名给出的证据，比写在选项描述里的效果好得多。
- 只有整轮请求成功后才会执行回调；请求失败时，页面和 frames 都不会被修改。

## 接入新的 Provider

```go
type Provider interface {
    ID() string   // provider/模型版本；它是缓存 key 的一部分，模型换了就要换 ID
    Judge(ctx context.Context, state interface{}, questions map[string]judge.Question) (map[string]judge.Answer, error)
}
```

- Provider 只负责把问题翻译成自己的协议并发送出去；缓存、合并、阈值和决策都不需要自己实现。可以参考 `judge/jev`（约 200 行）。
- 可选实现 `Calibrated`，返回在标注集上测出来的阈值：`Calibration() (threshold, versionConfidence)`。`judge.New` 会采用它，否则使用 0.5 / 0.9。
- 校准和对比：先在 `cmd/judgeeval` 的 `newProvider` 里注册，然后

  ```bash
  judgeeval -provider <name> -samples testdata/samples -labels testdata/labels.json
  ```

  用真值集调好阈值，再在真实页面上和纯规则做对比。

## 稳定性约定

- 对外 API：`New`、`Judge`、`Provider`、`Calibrated`、`Question`/`Answer` 及其构造函数、`Page`/`NewPage`、`Round`、`Verify`/`Classify`/`Version`/`Refine`、`Mark`/`Is`/`LayerOf`/`Judged`/`Accepted`/`PrimaryOf`、`Kind`、`Layer`、`Cache`/`NewMemoryCache`。
- tag 的写法（`judge:*`）和 `Kind`、`Layer` 的取值属于输出格式，不会随意变更。
- 问题的措辞、候选数量上限、版本号排序规则属于实现细节，可能随评测结果调整；每次调整都要用 `cmd/judgeeval` 回归。
