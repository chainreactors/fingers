# jevbench：纯规则 vs 规则 + Jev

在一批原始 HTTP 响应上，用和 SDK 调用方完全相同的路径（`engine.DetectContent` → `engine.Refine`）跑一遍，逐项对比纯规则结果和经过 Jev 判定之后的结果。

```bash
go build -buildvcs=false -tags goregexp -o jevbench ./cmd/jevbench

# 标注集（仓库自带 40 页，含真值）
TYPESAFE_API_KEY=... ./jevbench -samples testdata/samples -labels testdata/labels.json

# 任意真实页面目录（*.http，完整的原始响应）
TYPESAFE_API_KEY=... ./jevbench -samples cc/samples -cache jevcache -out jevreport -rps 15
```

- Jev 的回答按请求内容缓存在 `-cache` 目录（实现了 `jev.Cache` 的文件缓存），重跑不花钱，中断后可以接着跑。
- `jevreport/report.md`：对比表，另附页面类型分布、各引擎的否决率、否决率最高的规则（待修的规则），以及新指纹候选。
- `jevreport/rows.jsonl`：每页一行，列出规则命中、被接受的、被否决的、召回的、层级、主应用和版本号，用于人工复核。
- 给了 `-labels` 时，额外按真值统计误报剔除、真实命中保留、页面类型、通用页面和版本号的正确率。

没有真值的数据集用这两个代理指标：

- **仅正文出现的命中**：产品名只出现在可见正文里、不在任何结构字段中，是由代码判断出的疑似误报；
- **版本号**：以页面的 generator meta 作为参考答案。

真实网站的页面属于第三方内容，不要提交进仓库。
