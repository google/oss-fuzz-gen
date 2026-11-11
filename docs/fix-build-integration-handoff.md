# OSS-Fuzz 构建故障获取、元数据提取与自动修复：任务交接记录

最后更新：2026-09-30  
工作分支：`fix-fuzzing-build`  
工作仓库：`/root/temp/google_integration/true_repo/oss-fuzz-gen`

本文是此任务的持续维护记录。后续人员或 LLM 应先阅读本文，再查看本节列出的源码、
实验结果和未决事项。本文只记录已由源码、提交记录或实验产物支持的结论；不确定事项会
明确标为“未确认”。

## 1. 角色定义

本仓库需要提供一个可通过 OSS-Fuzz-Gen PR 实验运行的端到端系统。系统的职责分为三个
可独立、也可组合的阶段：

1. **日志获取阶段**：从 OSS-Fuzz build-status 服务发现当前失败项目，按规则下载构建日志。
2. **元数据提取阶段**：从已下载日志提取修复所需元数据；可选地复现历史构建，但复现
   不是生产部署中接纳元数据的前提。
3. **自动修复阶段**：将通过字段校验的 YAML 作为 benchmark，调用完整的
   `fix_build_agent` 修复 OSS-Fuzz 构建，并保留补丁、验证结果和报告数据。

系统不是 OSS-Fuzz 上游项目本身的维护者。它生成的是可验证的修复候选、补丁与 PR 描述
证据；是否被上游接受仍由上游审核决定。

## 2. 总目标与当前范围

### 总目标

将以下原本独立的能力集成进 `oss-fuzz-gen` 的 PR 实验流程，并可成功执行：

```text
OSS-Fuzz 状态/日志
  -> 下载与状态边界筛选
  -> 日志元数据提取（可选历史复现）
  -> 合格 benchmark YAML
  -> 自动化构建修复与补丁优化
  -> 结果、补丁、证据及 HTML 报告归档
```

### 当前范围

- 前置两阶段通过显式参数启用；不启用时保留原有静态 benchmark 修复行为。
- 三阶段既可分开调试，也可一次组合运行。
- 结果必须归档到 PR 实验结果目录，以便后续 HTML 报告和原始文件上传使用。
- 元数据缺少关键字段时，不能进入自动修复阶段。

## 3. 源码、来源工程与执行路径

### 3.1 当前集成后的源码入口

| 模块 | 当前源码 | 职责 |
|---|---|---|
| 参数解析与三阶段调度 | `run_all_experiments.py` | 定义 CLI 参数；先抓取、再提取、最后将生成的 benchmark 传入修复代理。 |
| 日志/元数据前置系统 | `experimental/build_fixer/pre_repair.py` | 日志获取、状态筛选、元数据提取、可选复现、字段校验、结果归档、黑名单。 |
| 前置系统测试 | `experimental/build_fixer/pre_repair_test.py` | 覆盖日志边界筛选、黑名单、字段顺序、SHA 选择、可选复现及缺失项目继续处理。 |
| 修复适配层 | `experimental/build_fixer/build_fix.py` | 将一个 benchmark 项目交给完整外部/内置修复代理。 |
| 完整修复工作流 | `fix_build_agent/agent.py` | 多代理构建修复、验证、失败路由、补丁优化与 LLM 调用。 |
| 修复辅助能力 | `fix_build_agent/agent_tools.py` | 日志、仓库、构建和补丁相关工具。 |

### 3.2 原始来源工程（用于追溯，不是当前运行时依赖）

| 原始路径 | 集成后的对应能力 |
|---|---|
| `/root/temp/google_integration/fuzz_error_log_acquisition` | `pre_repair.acquire_logs` 的状态发现和日志下载能力。 |
| `/root/temp/google_integration/reproduce_note_fuzz` | `pre_repair` 的日志解析、动态 OSS-Fuzz SHA 映射、可选历史复现思路。 |
| `/root/temp/google_integration/fuzz-logs-total` | 日志状态边界筛选原则。 |

原始 `reproduce_note_fuzz` 的 DeepSeek 调用不应作为当前运行依赖。当前集成的元数据分类和
可选错误比对使用 Vertex AI；使用提取阶段时必须传入 Vertex 模型。

### 3.3 实际调用链

```text
/gcbrun exp
  -> PR 实验容器/调度层
  -> run_all_experiments.py
       -> pre_repair.run_log_acquisition()                 [可选：阶段 1]
       -> pre_repair.run_reproduction_and_extraction()     [可选：阶段 2]
       -> ExternalBuildFixAgent / fix_build_agent           [可选：阶段 3]
  -> results/ 与 HTML/原始结果上传流程
```

`/gcbrun exp` 命令中的 `--` 是边界：前面是 GCB/PR 实验调度参数，后面是
`run_all_experiments.py` 的 oss-fuzz-gen 参数。不要跨越该边界传参。

## 4. 输入、筛选与输出契约

### 4.1 日志获取输入与 Key/All 模式

输入为 OSS-Fuzz build-status 服务公开的项目状态和构建日志 URL，以及可重复的
`--pre-repair-project <oss-fuzz-project-name>` 限定项。

- **Key 模式**（默认）：仅处理最新七条构建记录中同时出现成功和失败的当前失败项目。
  适合寻找近期由成功转为失败的项目。
- **All 模式**：处理当前失败项目；并在可获得时加入最后成功构建，随后进行状态边界筛选。
  适合保留当前失败链的上下文。
- 未指定项目时会扫描全部当前失败项目，并打印警告；调试时应指定项目。
- 指定项目若当前不失败，不是下载异常；会记录
  `project is not currently failing` 并跳过。

日志筛选不是固定日期样例。其规则是：连续错误段保留最早错误；连续成功段保留首尾成功；
同一天同时有成功和错误时两者都保留，并作为相邻状态段的边界。例如，一段连续错误日志不
会全部下载，而是仅保留能代表错误开始的那条。

### 4.2 自动与静态黑名单

静态黑名单定义在 `pre_repair.py` 的 `PRE_REPAIR_PROJECT_BLACKLIST` 中。当前名单为：

```text
commons-validator
libmediaart
protoreflect
tint
```

自动黑名单只在日志获取时判断：若项目**最新有效构建日志日期**严格早于“当前日期减一个
自然月”的日期，则本次运行跳过该项目。例如运行日是 2026-09-23，2026-08-22 及更早的
最新日志会被建议加入黑名单；2026-08-23 不会被加入。

每次获取阶段都会写出：

```text
results/pre_repair/pre_repair_blacklist.yaml
```

该文件仅列出自动发现、需要人工审查并通过 Git 提交加入静态名单的候选；它**不会自动修改
仓库源码**。若项目近期仍有失败构建，即使最后一次成功构建很久以前，也不会被列入黑名单。

### 4.3 元数据输入与接纳条件

第二阶段输入为第一阶段的 `acquired_logs/`，或由 `--pre-repair-log-dir` 指向的既有日志目录。
若未同时抓取日志，则必须提供 `--pre-repair-log-dir`；该参数不能与日志抓取参数共用。

原始审计元数据可包含 `last_success_time`，但最终 benchmark 不包含该字段，也不包含
`dependencies`。最终字段顺序为：

```yaml
project:
language:
error_time:
oss-fuzz_sha:
fuzzing_build_error_log:
software_repo_url:
software_sha:
engine:
sanitizer:
architecture:
base_image_digest:
error_category:
root_cause_commit:
root_cause_workspace:
fixed_state:
```

其中进入修复阶段必须非空的字段是：

```text
oss-fuzz_sha
software_sha
base_image_digest
fuzzing_build_error_log
software_repo_url
engine
sanitizer
architecture
```

`error_category` 和 `fixed_state` 会在提取阶段补充。动态 OSS-Fuzz SHA 映射覆盖运行日向前
三个自然月，并保留窗口前的锚点提交；对错误日期选择严格早于该日期的最新提交。

默认只提取元数据。`--pre-repair-verify-reproduction` 才会触发耗时的历史构建复现与 Vertex
错误比对。复现失败或不匹配会记录证据，但完整元数据不再因该条件被拒绝。

### 4.4 结果目录

所有前置产物位于实验结果中的：

```text
results/pre_repair/
  manifest.json
  pre_repair_blacklist.yaml
  acquired_logs/
  selected_logs/
  oss_fuzz_commit_mapping.json
  extraction-evidence.json              # 默认不复现
  reproduction-evidence.json            # 仅启用复现时生成
  metadata/
    original.yaml
    filtered.yaml
    rejected.yaml
  benchmarks/
    <project>.yaml
```

`manifest.json` 是排查首选：其中包含下载 URL、跳过项目、黑名单候选、筛选计数、错误和
最终 benchmark 目录。多个指定项目中，某些项目当前不失败或没有日志时，系统记录
`unavailable_requested_projects`，但会继续处理已成功取得日志的项目；仅在没有任何可处理
日志或没有任何通过字段校验的项目时失败。

## 5. 可直接运行的命令

以下命令均以 `/gcbrun exp` 为运行入口。每次实验必须使用新的 `-n` 名称。

### 5.1 仅抓取日志

单项目 Key：

```bash
/gcbrun exp -n acquire-single-key -- --fix-build-acquire-logs --pre-repair-project fwupd
```

单项目 All：

```bash
/gcbrun exp -n acquire-single-all -- --fix-build-acquire-logs --pre-repair-acquisition-mode all --pre-repair-project airflow
```

多项目 All：

```bash
/gcbrun exp -n acquire-multiple-all -- --fix-build-acquire-logs --pre-repair-acquisition-mode all --pre-repair-project airflow --pre-repair-project aiohttp
```

全量 Key（慎用）：

```bash
/gcbrun exp -n acquire-all-key -- --fix-build-acquire-logs
```

### 5.2 抓取并提取元数据（推荐调试路径，不复现）

单项目 Key：

```bash
/gcbrun exp -n acquire-extract-single-key -m vertex_ai_gemini-3-1-pro -ll global -- --fix-build-acquire-logs --fix-build-reproduce-and-extract --pre-repair-project fwupd
```

多项目 All：

```bash
/gcbrun exp -n acquire-extract-multiple-all -m vertex_ai_gemini-3-1-pro -ll global -- --fix-build-acquire-logs --fix-build-reproduce-and-extract --pre-repair-acquisition-mode all --pre-repair-project airflow --pre-repair-project aiohttp
```

要附加历史复现，只在上述命令末尾增加：

```bash
--pre-repair-verify-reproduction
```

### 5.3 从已有日志目录提取

```bash
/gcbrun exp -n extract-existing -m vertex_ai_gemini-3-1-pro -ll global -- --fix-build-reproduce-and-extract --pre-repair-log-dir <可访问的日志目录>
```

该模式不访问状态网站。`<可访问的日志目录>` 必须在 PR 实验运行环境中可读取；仅浏览器中
可见的 GCS URL 不等于可用的本地输入路径。

### 5.4 仅执行自动修复（已有静态 benchmark）

```bash
/gcbrun exp -n repair-static -m vertex_ai_gemini-3-1-pro -ll global -- --fix-build-agent --full-fix-build-agent --fix-build-benchmarks-directory <YAML目录>
```

`--full-fix-build-agent` 未指定外部路径时使用仓库内置的 `fix_build_agent`。若明确需要另一
个 checkout，可追加：

```bash
--external-fix-build-agent-path <fix_build_agent目录>
```

### 5.5 三阶段组合：抓取、提取、自动修复

```bash
/gcbrun exp -n acquire-extract-repair-multiple-all -m vertex_ai_gemini-3-1-pro -ll global -- --fix-build-acquire-logs --fix-build-reproduce-and-extract --fix-build-agent --full-fix-build-agent --pre-repair-acquisition-mode all --pre-repair-project airflow --pre-repair-project aiohttp
```

需要在修复成功后尝试优化补丁时，追加：

```bash
--fix-build-optimize-patch --fix-build-optimization-max-iterations 3
```

`--fix-build-optimize-patch` 必须同时使用 `--fix-build-agent` 和
`--full-fix-build-agent`。优化迭代数必须至少为 1，默认值为 3。

### 5.6 静态批量 YAML 的完整修复

当不运行前置动态流水线、而是直接使用仓库中的 `benchmark-sets/test_batch/` 时，可使用：

```bash
/gcbrun exp -n repair-static-test-batch -m vertex_ai_gemini-3-1-pro -b test_batch -ns 1 -nf 1 -d 0 -ll global -rd -- --fix-build-agent --full-fix-build-agent --fix-build-optimize-patch --fix-build-optimization-max-iterations 3
```

这里 `-b test_batch`、`-ns`、`-nf`、`-d` 和 `-rd` 是 `/gcbrun exp` 的外层调度参数，
不是 `run_all_experiments.py` 的参数；当前仓库无法证明它们的完整权威语义，运行前应以该
PR 实验环境的 `/gcbrun exp --help` 或维护者文档为准。`--` 后的参数才由本仓库解析。

## 6. 已完成工作与证据

### 6.1 已推送的前置系统提交

以下提交已推送到 `origin/fix-fuzzing-build`：

| 提交 | 内容 |
|---|---|
| `a9c21a8` | 修复历史前置元数据提取。 |
| `b639248` | 解除“复现匹配”对完整元数据接纳的硬依赖。 |
| `5b3214f` | 将历史复现改为可选。 |
| `c1f0fd3` | 修复前置元数据字段类型/别名问题。 |
| `302f049` | 规范化元数据字段与顺序。 |
| `d5dfe12` | 改进前置提取的可观察性和证据。 |
| `2472c5f` | 加入静态黑名单、基于一个自然月的自动候选及 `pre_repair_blacklist.yaml`。 |
| `830bf22` | 某些指定项目无日志时，继续提取其他可用项目。 |
| `dc5c72f` | 在修复代理中处理 Vertex 429：请求节流、退避、冷却和内部轮路由，并新增对应测试。 |
| `87ecb18` | 更新受漏洞影响的 Python 依赖版本。 |

### 6.2 已验证的前置实验

2026-09-29 的实验 `acquire-extract-multiple-all-logs-01` 使用：

```bash
/gcbrun exp -n acquire-extract-multiple-all-logs-01 -m vertex_ai_gemini-3-1-pro -ll global -- --fix-build-acquire-logs --fix-build-reproduce-and-extract --pre-repair-acquisition-mode all --pre-repair-project airflow --pre-repair-project aiohttp
```

结果已确认：

- 抓取、筛选、元数据提取均完成；`results/report.json` 的前置状态为 completed。
- `aiohttp` 和 `airflow` 均生成 benchmark YAML；`accepted_projects: 2`，
  `rejected_projects: 0`。
- All 模式为每个项目下载最后成功日志和当前错误日志，状态边界筛选后保留两条。
- 自动黑名单候选为空是正确结果：两个项目最新有效日志均为 2026-09-23，晚于该运行的
  阈值 2026-08-29；“最后成功日志较旧”不代表项目停止测试。
- 本实验未传 `--pre-repair-verify-reproduction`，因此没有进行历史构建复现，状态为
  `reproduction_verification_status: not_requested`。

### 6.3 当前静态批量 benchmark

当前仓库中可见的 `benchmark-sets/test_batch/` 有 12 个 YAML：

```text
bazel-rules-fuzzing-test, cups-filters, graphql-java, html5lib-python,
jsc, opencv, opentelemetry-go, opentelemetry-go-contrib, plexus-utils,
qemu, samba, time
```

这组静态 YAML 可用于仅修复实验；动态前置流水线会自行生成
`results/pre_repair/benchmarks/`，不依赖该目录。

## 7. 429 速率限制工作：状态与限制

历史批量修复出现过 Vertex `429 Too Many Requests` / `RESOURCE_EXHAUSTED`，即使项目层面
串行，单个修复工作流内的多个子代理仍会连续发起请求。

提交 `dc5c72f` 已实现以下 429 防护：

- 同一外部修复代理进程内，Vertex 请求单飞且最小间隔 6 秒；
- 仅对 LiteLLM `RateLimitError`、HTTP 429 或 `RESOURCE_EXHAUSTED` 进行处理；
- 首次失败后最多额外重试 4 次，共最多 5 次请求；退避基数为 30、60、120、240 秒，并有
  1.0–1.2 的随机抖动；
- 429 后施加进程内全局冷却；
- 重试耗尽后将当前内部修复轮路由为失败，尝试继续下一内部轮，而非直接抛出整个项目异常。

该提交包含 `fix_build_agent/agent_test.py` 的针对性测试。**尚未确认**的是最新完整 GitHub
CI 结果，以及该策略在真实多项目批量实验中的 429 发生率、重试次数、成本和最终修复率。
因此可以描述为“已实现并有单元测试的控制机制”，不能描述为“已证明消除了所有 429”。

## 8. 当前工作区状态与不可混入内容

写本文档时，已推送分支 HEAD 为 `87ecb18`。工作区另有未提交改动，不能在无明确授权时
混入后续前置系统/文档提交：

```text
D benchmark-sets/test_single_project/opentelemetry-go-contrib.yaml
?? benchmark-sets/test_single_project/cups-filters.yaml
?? docs/
```

其中 `docs/` 包含本交接文档和面向 OSS-Fuzz 的推广方案，尚待单独审查和提交；其余 benchmark
文件的来源和预期是否应提交，本文不作推断。提交任何修改前必须使用 `git status --short`、
`git diff -- <path>` 确认范围，并只 `git add` 已审查的目标文件。

## 9. 下一步执行顺序

1. **先验证三阶段组合**：对 1–2 个明确当前失败的项目运行“抓取 + 提取 + 完整修复”，
   检查 `results/pre_repair/benchmarks/` 是否被自动传递给修复代理，且报告中存在修复结果。
2. **验证已提交的 429 改动**：运行最新完整 GitHub CI，并先对 1–2 个项目做真实修复实验；
   确认 6 秒节流、429 重试、冷却和内部轮路由确实按预期写入运行日志。
3. **做小规模真实修复实验**：先串行 1–2 项，再增加项目数；统计每次 Vertex 调用次数、
   429 次数、重试次数、修复轮和最终状态。不要仅从总时长推断限额是否解决。
4. **检查完整 CI 与报告**：当前已验证 `pre_repair_test.py`，但本交接未取得最新完整 GitHub
   CI 结果。提交后需检查 GitHub presubmit，并确认 HTML 报告不会因前置产物缺失而失败。
5. **决定前置信息的 HTML 展示范围**：原目标要求后续在报告显示日志、筛选和元数据；本交接
   已确认文件归档和标准修复报告存在，但未确认当前 HTML 已展示前置 `manifest`/黑名单/元数据
   摘要。实现前应先检查报告代码与实际页面。
6. **再进行全量或长期批量实验**：只有小规模组合实验和速率限制证据稳定后，才运行不带
   `--pre-repair-project` 的全量扫描，避免无意义的状态扫描、日志下载和 Vertex 消耗。

## 10. 约束与安全规则

1. 只改动与当前故障或功能请求直接相关的文件；保留无关工作区改动。
2. 任何不确定的外部状态、模型可用性、GCB 参数语义、配额原因或上游构建结论，都必须先
   查看源码、运行日志或用户提供资料；不要凭空推断。
3. 对项目、日志 URL、元数据字段和 Git SHA 的判断，以 `manifest.json`、evidence 文件、
   原始日志和源码为证据。
4. 不自动把项目写入静态黑名单；仅写运行结果中的建议 YAML，人工审核后再提交。
5. 不要将 `--pre-repair-log-dir` 与 `--fix-build-acquire-logs` 同时使用。
6. 不要在未启用前置阶段时使用 `--pre-repair-project`。
7. `--pre-repair-verify-reproduction` 只能与 `--fix-build-reproduce-and-extract` 一起使用。
8. 仅有日志抓取时不要启动修复；若抓取后立即修复，必须同时提取元数据或明确提供静态
   benchmark 输入。
9. 不要额外传 `--work-dir` 改写 PR 实验管理的结果路径，否则结果上传/报告可能无法收集。
10. 每次外部实验使用新的 `-n`；保存完整的 `results/report.json`、
    `results/pre_repair/manifest.json`、相关 evidence 和修复日志，以便可追溯分析。
11. PR 实验操作应限定在分配的 `afg-pr`/PR 工作目录内；不要在上级目录或无关仓库中操作。
    不删除文件、不改动无关代码、不存储大型生成物。修改 requirements 或报告代码必须是本
    次功能所必需的最小变更，并以 PR 中代码状态为准进行实验。

## 11. 未确认事项（需要用户资料或下一次实验）

- `/gcbrun exp` 调度层专有参数（如历史命令中的 `-b`、`-ns`、`-nf`、`-d`、`-rd`）的精确
  语义不在本仓库的 `run_all_experiments.py` 中定义；本地环境也未发现可查询的 `gcbrun`
  命令帮助。后续如需编写这些参数的权威说明，应提供调度器文档或运行 `gcbrun exp --help` 的
  输出。
- 当前完整 HTML 报告是否已显示前置阶段摘要，尚未由实际页面或报告源码证实。
- 429 改动已提交，但其完整 CI 状态及对真实配额的效果仍未验证。
- 静态批量集之外的未提交 `cups-filters.yaml` 与删除的
  `opentelemetry-go-contrib.yaml` 是否是预期的用户改动，尚未确认。

## 12. 完成标准

本任务只有同时满足下列条件才可视为完整：

- 三阶段可单独运行、可组合运行，且不会改变未启用前置参数的普通实验行为；
- 动态日志到 benchmark 的链路可在真实失败项目上稳定完成；
- 合格元数据可自动进入修复代理，缺失字段项目不会进入修复；
- 429 防护有代码、测试、CI 和真实实验的证据；
- 修复结果、补丁、证据及前置产物均被正确归档，并在要求的报告范围内可见；
- 相关 CI 检查通过；
- 批量/全量运行前已有足够的小规模证据证明其成本、速率和失败处理可控。
