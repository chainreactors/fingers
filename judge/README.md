# judge：规则结果的判定层

`fingers.Engine` 只做规则检测。`judge.Judge` 接收规则命中和原始 HTTP 响应，由代码抽取候选、由 Provider（当前是 `judge/jev`）回答判断题，最后由代码做决定。输入的规则命中从不被修改。

```go
engine, _ := fingers.NewEngine()
j, err := jev.NewJudge("")                   // 读取 TYPESAFE_API_KEY；一个扫描任务共用一个 Judge
if err != nil { return err }
j.Known = judge.NewRetriever(engine.Names()) // 可选：召回规则漏掉、但名字出现在页面里的产品

hits, _ := engine.DetectContent(raw)
accepted, err := j.Refine(ctx, raw, hits)
if err != nil { accepted = hits }            // 判定失败时退回纯规则结果
```

## 三个入口

| 方法 | 用途 |
|---|---|
| `j.Refine(ctx, raw, hits)` | **要上报的结果**：去掉误报和重复写法，加入召回的产品，给每个保留的产品补版本 |
| `j.Inspect(ctx, raw, hits)` | **为什么**：全部命中及判定结论，包括被拒绝和重复的；不补版本 |
| `j.Classify(ctx, raw)` | **这是什么页面**：`Kind`（登录、错误、默认页……）和是否为产品标准页；Refine 之后命中缓存 |

其余能力：`j.Version(ctx, raw, f)` 单独给一个产品选版本；`j.IsUnknownProduct(ctx, raw, accepted)` 判断是否为尚无指纹的产品标准页；`j.SuggestNames(ctx, raw)` 从页面证据中提出产品名；`j.Yes/Choose/Score` 用来问自定义问题，state 可以是任意可 JSON 编码的值，比如 `judge.NewPage(raw)`。

## 判定结论

结论写在 `Framework.Judge`（定义在 `utils/parsers`）上，随现有输出一起序列化：

| 字段 | 含义 |
|---|---|
| `Layer` | 在技术栈中的层级：`judge.LayerCDN`、`LayerServer`、`LayerApplication` …… |
| `Confidence` | Provider 给出的"该产品确实参与生成此响应"的概率 |
| `Rejected` | 误报：只在页面文字中出现，或不存在。响应头或 Cookie 中出现的产品不会被拒绝 |
| `Duplicate` | 另一个引擎对已保留产品的不同写法 |
| `Primary` | 页面所属的主应用 |
| `Recalled` | 规则没报、由 `j.Known` 在页面中找到并经确认 |

`Judge == nil` 表示未经判定（每页超过 40 个产品时，多出的部分不判定），`frames.Accepted()` 会保留它们。

## 版本号

版本字符串一律由代码从原始响应中抽取，Provider 只做选择，不生成字符串：

1. 响应**按名字绑定**的版本直接采用，不提问：`Server: nginx/1.24.0`、`X-Jenkins: 2.401.3`、`X-Gitea-Version: 1.21.4`、`<meta name="generator" content="WordPress 7.0.3">`。名字按末尾词匹配，所以 `Apache Tomcat/9.0` 属于 Tomcat 而不是 Apache。
2. 其余产品在同一个请求里各问一题。候选按与产品名的接近程度排序（上下文提到产品名，紧挨版本前更好），插件、主题、第三方库路径降权；已按名字绑定给别的产品、且只出现一次的版本不会提供给它。
3. 只出现一次的版本字符串只归一个产品：上下文更贴近的优先，其次置信度更高的。置信度低于 `VersionConfidence` 的选择不采用。

## 缓存与成本

答案按问题缓存，同一问题不会重复发送，无论它被放进哪次请求。标题相同、签名相差不超过 `j.SimilarDistance` 位（默认 1）的页面共享答案，同一产品在不同主机上的登录页只问一次；并发的相同请求会合并。`j.Cache` 默认是内存 LRU，实现 `judge.Cache` 即可换成共享存储。`j.Requests`、`j.CacheHits` 用于成本监控。

## 自定义 Provider

实现 `ID() string` 和 `Judge(ctx, state, map[string]judge.Question) (map[string]judge.Answer, error)` 即可，可选实现 `Calibration() (threshold, versionConfidence float64)`。问题分三类：`TypeBinary`（是的概率）、`TypeChoice`（从选项中选一个）、`TypeScore`（有序等级上的分数）。缓存、并发合并和阈值决策都在 `Judge` 中完成，因此不同 Provider 的行为一致。新 Provider 需在 `cmd/judgeeval` 的 `newProvider` 注册并跑一遍评估来校准阈值。

## 数据外发

发给 Provider 的是响应的精简视图：响应头（去掉 Date、Set-Cookie 等无关或易变的头）、Cookie 名、标题、generator/description、脚本和样式路径、内联脚本开头、HTML 注释、表单字段名，以及正文前 1500 字。扫描前请确认允许把这些内容发送给第三方服务。

## 生成指纹

`judge/gen` 用正反样本生成原生 `*fingers.Finger`：

```go
g := gen.New(j).
    PositiveVersion(jenkinsA, "2.401.3").
    PositiveVersion(jenkinsB, "2.402.1").
    Negative(otherProduct)
finger, err := g.Generate(ctx) // 可直接用于现有规则引擎
err = g.Validate(finger)       // 编辑规则后，再按全部正反样本验证
```

至少需要一个正样本和一个反样本。不给 `Name` 时，由 `SuggestNames` 从正样本中选名字；`Probe`/`ProbeWith` 记录主动探测的请求和响应。`Validate` 只运行规则引擎、不调用模型，也不会写入模板仓库。
