# judge: 显式判定 API

`fingers.Engine` 只做规则检测。`judge.Judge` 接受规则命中和原始 HTTP 响应，调用 Provider（当前提供 `judge/jev`），以代码确定最终语义。判定结果是新对象，原始规则命中保持不变。

```go
engine, _ := fingers.NewEngine()
j, err := jev.NewJudge("") // TYPESAFE_API_KEY；一个扫描任务共用一个 Judge
if err != nil { return err }

hits, err := engine.DetectContent(raw)
if err != nil { return err }
accepted, kind, generic, err := j.Refine(ctx, raw, hits)
if err != nil { return err } // hits 仍可作为纯规则结果使用
fmt.Println(accepted, kind, generic)
```

## 能力与语义

| API | 含义 |
|---|---|
| `j.Yes(ctx, state, question)` | 返回“是”的概率，`float64`，不是布尔判决 |
| `j.Choose(ctx, state, question, options)` | 从给定选项中选一个，返回选项和置信度 |
| `j.Score(ctx, state, question, levels...)` | 按有序等级返回 0 到 1 的分数 |
| `j.Verify(ctx, raw, hits, knownNames...)` | 核验产品是否存在、归并同名、判断层级和主应用，返回接受的指纹 |
| `j.Inspect(ctx, raw, hits, knownNames...)` | 返回所有规则命中及拒绝、重复、层级、主应用等诊断标记 |
| `j.Classify(ctx, raw)` | 返回页面类型 `Kind` 和是否为产品标准页面 |
| `j.Version(ctx, raw, framework)` | 在响应中的版本候选里选择该产品的版本；不修改输入 |
| `j.Refine(ctx, raw, hits, knownNames...)` | 核验、分类并为主产品选择版本；返回指纹、类型和标准页面判断 |
| `j.IsUnknownProduct(ctx, raw, accepted)` | 标准产品页面但没有已确认的应用或设备时返回 true |
| `j.SuggestNames(ctx, raw)` | 从本页头、标题、资源和正文提取候选，并判断哪些是产品名 |
| `judge.NewGenerator(j)` | 用正反样本生成原生 `*fingers.Finger` |

`state` 是任意可 JSON 编码的值。判断 HTTP 页面时，可以传 `judge.NewPage(raw)` 的结果。`Verify` 与 `Refine` 不修改 `hits`，失败时也不会返回部分判定结果。需要看到被剔除的条目时用 `Inspect`，再以 `judge.Is`、`judge.LayerOf`、`judge.PrimaryOf` 读取标记。

`knownNames` 是调用方明确给出的**已有**产品名候选。`judge.NewRetriever(names).Find(page.Haystack(), limit)` 可在页面中查找现有别名。它只做已知名称召回；`IsUnknownProduct` 和 `SuggestNames` 是独立能力。后者只返回本页可提取的名字，不能还原已彻底改名且没有原名证据的产品。

`Refine` 通常发两轮请求：第一轮核验与页面分类，第二轮为已确认的主产品挑版本。答案按问题缓存，相似页面可共享。Provider 缺少任何被请求的答案时，整轮失败。

## 生成指纹

```go
g := judge.NewGenerator(j).
    PositiveVersion(jenkinsA, "2.401.3").
    PositiveVersion(jenkinsB, "2.402.1").
    Negative(otherProduct)

finger, err := g.Generate(ctx) // *fingers.Finger，可直接用于现有规则引擎
if err != nil { return err }
err = g.Validate(finger)        // 编辑规则后，再按全部正反样本验证
```

至少需要一个正样本和一个反样本。`Name("Jenkins")` 可以给出已知名称；缺省时从正样本调用 `SuggestNames` 自动选择。`PositiveVersion` 提供版本真值；普通 `Positive` 在有 Judge 时会尝试从页面候选中高置信度选版本。版本规则只有在样本证据足以构造并验证提取式时才会生成。

主动探测以原始 `send_data` 和对应的完整 HTTP 响应记录：

```go
g := judge.NewGenerator(j).Name("Orion").
    Positive(home).Probe([]byte("/admin"), adminResponse).
    Negative(otherHome).Probe([]byte("/admin"), otherAdminResponse)
finger, err := g.Generate(ctx)
```

`ProbeWith(ctx, request, send)` 可由调用方提供在线发送函数。主动规则需要同一请求的正反响应；`Validate` 通过现有 `Finger.Match` 执行被动与主动规则，不调用模型，也不会写入模板仓库。无法区分正反样本时，`Generate` 返回错误。

## 自定义 Provider 与批量问题

Provider 只需实现 `ID() string` 和 `Judge(ctx, state, map[string]judge.Question) (map[string]judge.Answer, error)`。可选实现 `Calibration() (threshold, versionConfidence float64)`。Jev 适配器把二元问题映射到 `noul`，把选择和评分映射到 Jev 对应类型；缓存、并发合并和阈值决策在 `Judge` 中完成。

自定义问题可通过 `j.Yes`、`j.Choose`、`j.Score` 单独调用。需要把多个问题合并为一次请求时，使用 `page.Round()`、`Round.Add` 和 `Round.Ask`；它是高级组合接口，`Question`/`Answer` 仅服务于 Provider 和批量扩展。
