# judgeeval：纯规则 vs 规则 + judge

## 可回放真实数据评估

`-manifest` 模式覆盖保存结果清洗、逐产品补全版本、名称召回和原生指纹生成，结果写入独立目录。

```powershell
# urls.txt 每行一个 URL；新采集用新目录。IP 证书不匹配时显式加 --insecure。
python scripts/capture_judge.py --urls urls.txt --out .judge-data/corpus --workers 6
go build -o bin/judgeeval.exe ./cmd/judgeeval
# TYPESAFE_API_KEY 仅通过进程环境提供。
./bin/judgeeval.exe -manifest .judge-data/corpus/manifest.json -cache .judge-data/cache -out .judge-data/run-01 -rps 8
# 同一快照及原结果用于验证历史清洗机制。
./bin/judgeeval.exe -manifest .judge-data/corpus/manifest.json -history .judge-data/run-01/baseline.jsonl -cache .judge-data/cache -out .judge-data/run-02
# 用运行目录内归档的响应严格离线复现；无须 API key，缓存未命中直接失败。
./bin/judgeeval.exe -offline -manifest .judge-data/run-02/manifest.json -history .judge-data/run-02/baseline.jsonl -cache .judge-data/cache -out .judge-data/run-offline
```

采集器保存完整响应、来源、时间、SHA256 和失败记录，不自动跳转。第三方原文保存在 git 忽略的 `.judge-data/`。输出目录不能复用覆盖。

### 标注

为 manifest 的每份快照填写 `labels`：`product`、`present`、原文片段 `evidence` 和结论依据 `basis`。`version` 缺省表示未标注；空字符串表示未声明版本；非空字符串为准确版本。`aliases` 显式列出同义名，计分不使用子串匹配。加载时验证响应哈希及证据片段，片段是否足以支持结论仍需评审。

格式示例（仅示意，不作为真实数据）：

```json
{"product":"Apache","aliases":["apache http server"],"present":true,"version":"2.4.38","evidence":["Server: Apache/2.4.38"],"basis":"响应头声明产品和版本"}
```

真值范围是响应证据支持的产品与版本，不等价于主机安装审计。标注来自响应头、generator meta、资源路径和人工评审；不以 Jev 回答作真值，不向清洗和版本判定传入标签。

### 生成与独立验证

`generation` 每项填写 `name`（输出文件名）、`product`、`auto_name`、`positive`/`negative`（训练快照 ID）。其他有该产品标注的快照用于测试；排除训练主机、相同响应和重复测试响应。使用普通 `Positive` 自动推断版本，测试标签只打分。

主动规则另填 `probe`（请求字符串），各样本 `probes` 将请求映射到同主机已采集响应 ID。回放不发送网络请求。导出 YAML 后重新加载、编译并验证。结论为 `passed_holdout`、`failed_holdout`、`insufficient_holdout`；至少需要独立正反例且版本无错漏才能在本批次通过。单主机新产品仅能产生待验证草案。生成文件供审阅，不自动写入指纹库。

### 输出

- `manifest.json` / `samples/*.http` / `build.json`：本次实际输入及 Go 构建信息，响应可独立加载；离线模型答案仍需同时保留 `-cache` 目录。
- `baseline.jsonl`：原生 Frameworks，来源是当前规则或 `-history`。历史记录按 ID、SHA256 严格对齐，缺失即报错。
- `cleaned.jsonl`：成功清洗并补版本的原生 Frameworks。
- `rows.jsonl`：基线、Refine 及拒绝/合并/新增/补版本/错误。
- `metrics.json` / `report.md`：标注范围内的 TP/FP/FN/TN、误删、自然漏报恢复、版本正确/错误/缺失/无依据填值。失败和未标注输出单列。
- `generation.json` / `fingerprints/*.yaml`：候选指纹、独立验证结果及排除的样本。

`Refine` 给每个保留产品补版本；报告比较原结果和 Refine 两个阶段。已有非空版本保留，错误由报告揭示。缓存按模型、endpoint、完整 state 和问题精确复用，评估不使用近似页面缓存。

新增版本按产品及显式别名合并计数，原基线任一别名已有版本即不算新增。名称建议单独统计，不能算作已补回漏报。生成器训练样本的自动版本结果在 `training_versions` / `training_cases` 单列，错误时标记 `failed_training`；训练标签只在导出后打分。

新采集快照的历史回放验证的是清洗机制，不代表已验证生产历史分布。样本量、同主机依赖和标签覆盖范围必须随指标报告。

### 维护原生指纹库

`-maintain` 在同一次 manifest 回放中核验新产品、生成原生 YAML、验证候选，再通过实际引擎加载新增指纹。`-library` 明确指定本地已有扩展库，先加载再评估；不要求新增 SDK 请求/响应结构。

```powershell
# 审核新增产品并输出本次通过验证的增量库。
./bin/judgeeval.exe -maintain -manifest .judge-data/corpus/manifest.json -cache .judge-data/cache -out .judge-data/maintain-01
# 下一轮维护使用已有库作为基线，防止重复收录。
./bin/judgeeval.exe -maintain -library .judge-data/maintain-01/library.yaml -manifest .judge-data/corpus/manifest.json -cache .judge-data/cache -out .judge-data/maintain-02
# 完整离线复现；如果原运行用了扩展库，也必须传入归档的 input-library.yaml。
./bin/judgeeval.exe -offline -maintain -library .judge-data/maintain-02/input-library.yaml -manifest .judge-data/maintain-02/manifest.json -history .judge-data/maintain-02/baseline.jsonl -cache .judge-data/cache -out .judge-data/maintain-offline
```

新增被动指纹的收录条件：

1. 在五个内置 HTTP 引擎目录、别名表和实际加载的 fingers 运行时目录中均无同名产品。按规范名及显式别名审计，记录各目录 SHA256；并非覆盖所有外部指纹源。
2. 普通 `Positive` 自动推断名称和版本，通过训练集、独立正反例、版本验证；不把标签版本传给生成器。
3. 至少两个独立正例主机组、五个独立反例主机组。相同主机名或同属一个 `group` 的样本合并计数，且排除训练主机和重复内容。
4. 调用 `engine.Fingers().LoadFromYAML(...)` 和 `engine.Compile()` 后重放全部样本。新增产品的标注识别/版本必须全部正确，已有命中和非空版本必须保留。

输出 `catalog-before.json`、`maintenance.json`；通过时再将 `library.candidate.yaml` 提升为 `library.yaml`。已有产品为 `already_catalogued`；没有足够独立样本的候选保留为 `insufficient_holdout` 或 `insufficient_independent_hosts`，不会混入输出库。主动规则暂不进入此被动库维护流程。`-library` 的原文另存 `input-library.yaml`，便于准确复现。

此收录检查验证**原生规则加载**。加载后再由 Jev 清洗是否误删、错误召回或错误补版本，要用上述第二轮当前规则基线单独验证；见 `rows.jsonl` / `metrics.json`，不能把去重成功当成整个清洗链路准确。扩展库需要调用方显式加载，命令不重写内置压缩资源或发布外部仓库。


## 目录模式

在一批原始 HTTP 响应上，用和 SDK 调用方完全相同的路径（`engine.DetectContent` → `j.Refine`）跑一遍，逐项对比纯规则结果和经过判定之后的结果。它也用来校准新的 Provider。

```bash
go build -buildvcs=false -o judgeeval ./cmd/judgeeval

# 标注集（仓库自带 40 页合成样本，含真值）
TYPESAFE_API_KEY=... ./judgeeval -provider jev -samples testdata/samples -labels testdata/labels.json

# 任意真实页面目录（*.http，完整的原始响应）
TYPESAFE_API_KEY=... ./judgeeval -provider jev -samples cc/samples -cache judgecache -out judgereport -rps 15
```

- 答案缓存在 `-cache` 目录，重跑不花钱，中断后可以接着跑。这个目录用的是精确缓存，另外会模拟相似度缓存：按签名距离分档，统计每一档能复用多少答案、与真实答案的一致率，用来确定 `Judge.SimilarDistance` 的取值。
- `report.md`：对比表，另附页面类型分布、各引擎的否决率、否决率最高的规则（需要修复），以及新指纹候选。
- `rows.jsonl`：每页一行，用于人工复核。
- 给了 `-labels` 时，额外按真值统计误报剔除、真实命中保留、页面类型、通用页面和版本号的正确率。
- 新 Provider：在 `main.go` 的 `newProvider` 里注册。

没有真值的数据集用两个代理指标：
- **仅正文出现的命中**：代码判断出的疑似误报；
- **版本号**：以页面上的 generator meta 作为参考答案。

真实网站的页面属于第三方内容，不要提交进仓库。
