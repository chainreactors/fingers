# judge：以 Claim 审查规则结果

规则引擎负责检测；judge 在线只审查产品是否参与生成响应，以及响应能否确认版本。Provider 从有限选项中选择，不生成产品名或版本字符串。离线审计、聚类与生成分别放在 `judge/maintain` 和 `judge/gen`，复用同一 Claim 合约。

Claim 合约（Claim / Option / Outcome / Ruling / Provider）、校验、缓存和 Jev 客户端都在 [`github.com/chainreactors/utils/jev`](https://github.com/chainreactors/utils/tree/master/jev)。本包只定义指纹相关的断言：presence、version 和离线的 coverage，以及代码确定的事实如何表达成 Ruling。

## 代码确定的事实

代码确定的产品、协议和版本事实也构建合法 Claim/Ruling（置信度 1），经相同的 `Resolve` 和应用函数执行。重复写法的归并是 bookkeeping，不是 Claim。

## 在线入口

```go
engine, _ := fingers.NewEngine()
engine.EnableMatchDetail()
c, err := jev.NewClient("") // TYPESAFE_API_KEY
if err != nil { return err }
j := judge.New(jev.Cached(c, jev.DefaultCacheSize)) // 一个扫描任务共用

hits, err := engine.DetectContent(raw)
if err != nil { return err }
all, err := j.Inspect(ctx, raw, hits)
accepted := all.Accepted()
// all 同时保存接受、拒绝、重复及未判定条目；出错时保留已完成的结果。
```

`Inspect` 完成 presence 和 version，最多两个 Provider 批次。报告直接读这份结果，不再执行第二次判断。输入会复制，重新评估会清除旧 presence 注解。解析错误返回复制的基线和错误；Provider 失败时保留已确定事实和去重信息，尚未判断的条目没有 Outcome。输入中已有非空版本保持原值。

| 入口 | 用途 |
|---|---|
| `Inspect(ctx, raw, hits)` | 所有命中及 presence 注解，保留产品的版本补全 |
| `all.Accepted()` | 排除 Rejected / Duplicate 的结果视图，不调用 Provider |
| `Version(ctx, raw, f)` | 为生成工具单独确认版本，不修改 f |

Presence 用 `running` 表示产品参与生成响应，`mentioned` / `unrelated` 表示误报。协议事实从完整响应头读取；产品确定事实限于明确的软件声明和产品专属头，Location、Cookie 中的名称只作为待审证据。版本从响应中抽取，每个产品只有一个多选 Claim：候选版本、`not_stated`、`insufficient`。按名字声明的版本走本地 Ruling；其他版本由 Provider 选择。每页最多向 Provider 提交 40 个 presence Claim，最多为 8 个产品确认版本，每个产品最多展示 15 个候选。

`Framework.Judge` 是输出注解，沿用现有 common 类型：

| 字段 | 含义 |
|---|---|
| Option | 原始选项；即使置信度不足也保留 |
| Outcome | Resolve 后的 holds / refuted / insufficient；消费方按此统计 |
| Confidence / Evidence | 置信度及规则命中原文；本地确定事实置信度为 1 |
| Rejected | Refuted，或 Insufficient 且 DropInsufficient 为 true |
| Duplicate | 同一产品的其他写法；即使尚未判定也可标记 |

`judge.New(p)` 默认 `MinConfidence=jev.DefaultMinConfidence`（0.3）、`DropInsufficient=false`。策略和 Provider 配置应在并发扫描前确定。Version 在证据不足时不填值。

## 离线维护

- `maintain.Ledger.Add(id, all)` 从既有 presence 注解汇总规则表现，不再请求 Provider。`Report` 返回深复制快照，记录 Outcomes、Options 和样本 ID；`Hits()` 与 `RefutedFraction()` 从 Outcomes 推导。Presence 选项常量统一为 `judge.OptionRunning` 等 `Option*`，原生 `Framework.Judge.Option` 输出字段继续保留。当前引擎聚合后的 MatchDetail 仍只保留首个匹配详情，未重设计完整规则来源。
- `maintain.Discover` 按资源路径、表单、Cookie/自定义头名和页面文字等结构特征聚类。每个多主机簇提出 Coverage Claim：`explained` / `custom_site` → Holds，`missing` → Refuted，另有 insufficient。Cluster 直接可序列化，仅保存成员 ID、Coverage 原始 Ruling、解析的 Outcome、已报告产品和代码抽取的候选名。候选名供人命名，不作为 Provider 选项。
- `gen.Generator` 为人指定的 Name 从正反样本生成规则。需要时调用 Version。Validate 运行规则引擎，不调用模型，不修改内置库。

`cmd/judgeeval` 两种输入模式共用 `baseline` / `judged` 行记录。接受结果、拒绝项、版本差异和指标均从它们派生，聚类通过样本 ID 关联。生成评估同样保存原生 Framework，以 manifest 为唯一标签来源，分数和状态按需推导。报告 schema 为 3，统计使用 `claims/options`；旧缓存因命名空间隔离不会被复用。详见 [judgeeval](../cmd/judgeeval/README.md)。

Provider 收到精简响应视图、规则命中上下文和版本候选上下文；完整原始响应仍仅在本地用于解析事实与提取证据。
