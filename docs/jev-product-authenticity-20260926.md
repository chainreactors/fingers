# 三个新增指纹的产品真实性复核

## 结论

**SearXNG、Wakapi、IT Tools 都是真实存在、有公开源码及实际部署的项目。** 本批“新产品”指当前已审计指纹库中的新增识别对象，不代表软件近期发布，也不代表首次在全球被识别。

| 产品 | 官方仓库 | 仓库创建日期（UTC） | 本批指纹的准确语义 |
|---|---|---|---|
| SearXNG | `searxng/searxng` | 2021-04-12 | SearXNG 产品识别；从 generator 声明提取版本 |
| Wakapi | `muety/wakapi` | 2019-05-21 | Wakapi 产品识别；结合标题与资源/页脚证据提取版本 |
| IT Tools | `CorentinTh/it-tools` | 2020-04-05 | **IT Tools 产品家族识别**；无法区分原版与衍生版，版本留空 |

日期来自 GitHub 仓库 API 的 `created_at`，不是首次发布日。API 和源码复核时间为 2026-09-25 17:02–17:06 UTC，即北京时间 2026-09-26 01:02–01:06。部署证据复用上一轮已归档的真实 HTTP 响应。

## SearXNG：身份和生成标记相互印证

- 官方仓库：[searxng/searxng](https://github.com/searxng/searxng)。官方 README 将其定义为元搜索引擎。
- 官方模板 `searx/templates/simple/base.html` 第 8 行生成 `name="generator"`、`content="searxng/{{ searxng_version }}"`；第 72 行也显示产品名及版本。
- 官方 `searx/infopage/en/about.md` 第 49 行说明 SearXNG 源自 Searx 的分支。应保留 SearXNG 独立产品身份，不能把名字包含 Searx 的页面全部认作 SearXNG。
- 本批 10 份 SearXNG 正例均包含对应 generator，包括定制标题的实例。规则依赖产品声明，不要求站点标题恰好叫 SearXNG。

固定源码证据：[模板 blob](https://api.github.com/repos/searxng/searxng/git/blobs/abad3f141daaecf0465211c463319beaac30ce39)、[项目关系说明 blob](https://api.github.com/repos/searxng/searxng/git/blobs/486b2617595ee91d50853163af983a4329ee09aa)。

**判定：真实产品，本次库内新增身份成立。** generator 是应用自行声明的证据，不等同于主机安装审计或不可伪造的版本证明。

## Wakapi：独立应用，兼容 WakaTime

- 官方仓库：[muety/wakapi](https://github.com/muety/wakapi)。官方 README 第 14 行说明它是兼容 WakaTime 的自托管编程统计后端。
- 官方 `views/head.tpl.html` 第 2 行使用 `Wakapi – Coding Statistics` 标题，与本批 4 份正例一致。
- 模板第 18 行使用 `assets/css/app.dist.css?v={{ getCacheBuster }}`；`views/footer.tpl.html` 第 3 行通过 `getVersion` 输出版本。缓存参数须结合具体响应验证，不能仅因出现 `?v=` 就认定它是产品版本。
- 本批样本包括项目主页及三个独立测试站点；版本提取结果见[原验证报告](jev-maintenance-validation-20260926.md)。
- 内置 Wappalyzer 的 `Wakav Performance Monitoring` 是另一项监控产品，不能因前缀相似认作 Wakapi。兼容 WakaTime 也不等于 Wakapi 是 WakaTime 的别名。

固定源码证据：[README blob](https://api.github.com/repos/muety/wakapi/git/blobs/ce5f15f2198397dd5b41a6a1eb1be08ccab0d626)、[页面头模板 blob](https://api.github.com/repos/muety/wakapi/git/blobs/12f24762324fece08a9ccad1ba9265556c62aeaa)、[页脚模板 blob](https://api.github.com/repos/muety/wakapi/git/blobs/3d50040e195b1792925994163c6b7c0139ebe022)。

**判定：真实产品，本次库内新增身份成立。**

## IT Tools：真实项目，当前指纹仅识别产品家族

- 原项目：[CorentinTh/it-tools](https://github.com/CorentinTh/it-tools)，开发者在线工具集合。官方 `index.html` 第 7 行即当前规则使用的完整标题。
- 衍生项目：[sharevb/it-tools](https://github.com/sharevb/it-tools)。GitHub API 返回 `fork: true`，`parent.full_name` 为 `CorentinTh/it-tools`，仓库创建于 2023-11-30。这不是本批额外发现的第四个独立产品。
- 衍生版 `index.html` 第 26 行保留相同标题，第 37 行的 `og:url` 指向 `https://sharevb-it-tools.vercel.app/`。

| 本批样本 | 直接观察 | 能够支持的结论 |
|---|---|---|
| `it-tools.tech` | 完整产品标题；`og:url` 指向项目主页 | 原项目官方站点样本 |
| `tools.code.pro.vn` | 同一标题；`og:url` 改为当前站点 | IT Tools 家族，具体分支未确定 |
| `tools.quitw.org` | 同一标题；`og:url` 指向 sharevb 主页 | 携带 sharevb 衍生版元数据，不能仅凭该信息确定精确代码分支或版本 |

固定源码证据：[原版 index.html blob](https://api.github.com/repos/CorentinTh/it-tools/git/blobs/e8b8a60ea6f6864ea062874c4d6e84cbea608de6)、[衍生版 index.html blob](https://api.github.com/repos/sharevb/it-tools/git/blobs/7e0246142e9818a8745d758aed6bd9429c221546)。分支关系来源：[仓库 API](https://api.github.com/repos/sharevb/it-tools)。

**判定：真实项目，本次库内新增家族级识别成立。当前规则只匹配标题，不能宣称三个站点都是 CorentinTh 原版，也不能据此补具体版本。** 原报告的 IT Tools 正例和 FP/FN 应按家族级标签理解；若目标改为原版或指定分支，需要重新标注和验证，原指标不能直接沿用。

## “库内新增”的核查范围

复核 `run-07-final/catalog-before.json` 的五个内置 HTTP 目录、别名及运行时 fingers 目录，再对以下文件进行全文检查：

- `resources/fingers_http.json.gz`
- `resources/goby.json.gz`
- `resources/ehole.json.gz`
- `resources/wappalyzer.json.gz`
- `resources/fingerprinthub_web.json.gz`
- `resources/aliases.yaml`

解压后忽略大小写，检索 `searx|waka|it[\s_-]*tools|corentinth|sharevb|handy[\s_-]*online`。只有 Wappalyzer 中同一个 `Wakav Performance Monitoring` 条目的五处文本命中；其余为零。未发现三个产品的同名、显式别名或上述身份标记。

结合此前原生检测的新增前漏报、加载后的命中，以及重复维护时三项均成为 `already_catalogued`，支持“本次审计范围中的新增指纹”。不覆盖外部所有指纹库；关键词检查也不能排除不含这些标记的规则存在语义重合。

## 证据与变更

完整证据位于本地 `.judge-data/product-authenticity/`：

| 文件 | 内容 |
|---|---|
| `repositories.json` 与四份仓库原始 JSON | 官方来源、创建时间、分支关系、采集时间、SHA256 |
| `source-tree-index.json` 与四份 tree JSON | 源文件定位、Git tree SHA、完整性标志 |
| `source-evidence.json` 与 `source/` | 官方源码、Git blob SHA、SHA256、证据行号 |
| `deployment-evidence.json` | 17 份正例的响应路径、URL、SHA256、身份标记 |
| `library-fulltext-audit.json` | 六个本地资源的 SHA256、检索命中及上下文 |

17 份部署响应的 SHA256 均与原 manifest 一致。其中包含训练样本，不是新增盲测样本数量。本次复核补充官方来源和身份范围，没有增加识别准确率或覆盖率声明。

本次仅新增证据和文档说明；原指纹 YAML、历史标签及评估结果保持原样。YAML 的 SHA256 仍为 `522a85806592e10bdffa87ccb70be90e22098fdeba85cc52452235132520065a`。
