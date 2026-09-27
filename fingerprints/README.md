# 经真实响应验证的 Jev 增量指纹

本目录保存通过 `judgeeval -maintain` 生成、导出、重新编译、独立样本测试及原生加载检查的原生 YAML。每个文件附带数据来源、目录审计和验证范围；默认引擎的内置压缩资源仍按原有资源流程维护。

## 加载

```go
engine, err := fingers.NewEngine(fingers.FingersEngine)
if err != nil {
    return err
}
if err := engine.Fingers().LoadFromYAML("fingerprints/jev-maintained-20260926.yaml"); err != nil {
    return err
}
if err := engine.Compile(); err != nil {
    return err
}
hits, err := engine.DetectContent(rawHTTPResponse)
```

生成规则维持原生 `Finger` / `Frameworks` 语义。SearXNG 和 Wakapi 包含版本提取；IT Tools 当前按完整标题识别产品家族，覆盖原版与保留该标题的衍生版，不能区分具体分支，版本留空。

三个项目均经官方仓库和源码复核；“新增”仅指本次已审计的指纹库范围，不是近期发布的新软件。身份依据和分支范围见[产品真实性复核](../docs/jev-product-authenticity-20260926.md)。

扩展测试报告见 [Jev 指纹库维护验证](../docs/jev-maintenance-validation-20260926.md)，运行数据和完整响应保存在本地 `.judge-data/expansion-20260926/`。这些指纹的结论仅适用于报告中列出的版本、样本和标注范围。
