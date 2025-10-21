# 如何运行 LangGraph Workflow

测试 cJSON 项目的快速指南

---

## 🚀 快速开始

### 方法 1: 使用 LangGraph 主入口（推荐）

```bash
# 基本运行 - 处理 cJSON_Parse 函数
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat
```

### 方法 2: 使用传统 run_single_fuzz.py + agent 模式

```bash
# 需要先设置环境变量（如果使用本地 AI）
export AI_BINARY=/path/to/ai/binary  # 可选

# 运行 LangGraph workflow
python3 run_single_fuzz.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat \
  --agent
```

---

## 📋 命令参数说明

### 必需参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-y, --benchmark-yaml` | Benchmark YAML 文件路径 | `-y conti-benchmark/cjson.yaml` |
| `-f, --function-name` | 要测试的函数名 | `-f cJSON_Parse` |
| `--model` | LLM 模型名称 | `--model vertex_ai_gemini-2-5-pro-chat` |

### 可选参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--workflow-type` | Workflow 类型 | `full` |
| `--trial` | Trial 编号 | `0` |
| `--max-iterations` | 最大迭代次数 | `5` |
| `--run-timeout` | 运行超时时间（秒） | `60` |
| `--context` | 添加上下文信息 | `false` |
| `-v, --verbose` | 详细日志 | `false` |

---

## 🎯 完整示例命令

### 1. 测试 cJSON_Parse（基础）

```bash
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat
```

### 2. 测试 cJSON_ParseWithLength（带上下文）

```bash
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_ParseWithLength \
  --model vertex_ai_gemini-2-5-pro-chat \
  --context
```

### 3. 详细日志 + 自定义迭代次数

```bash
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat \
  --max-iterations 10 \
  --run-timeout 120 \
  --verbose
```

### 4. 处理 YAML 中的所有函数

```bash
# 不指定 -f 参数，会处理所有函数
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  --model vertex_ai_gemini-2-5-pro-chat
```

---

## 🔧 可用的 LLM 模型

根据 `llm_toolkit/models.py`，可用的模型包括：

### Vertex AI (Google Cloud)
```bash
--model vertex_ai_gemini-2-5-pro-chat
--model vertex_ai_gemini-1.5-flash
--model vertex_ai_gemini-1.5-pro
```

### OpenAI
```bash
--model gpt-4o
--model gpt-4-turbo
--model gpt-3.5-turbo
```

### Claude
```bash
--model claude-3-5-sonnet
--model claude-3-opus
```

---

## 📂 输出目录结构

运行后会在 `results/` 目录下创建输出：

```
results/
└── output-cjson-cJSON_Parse/
    ├── benchmark.yaml              # 使用的 benchmark 配置
    ├── status/                     # 运行状态
    ├── raw-targets/               # 生成的原始代码
    ├── fixed-targets/             # 修复后的代码
    ├── code-coverage-reports/     # 覆盖率报告
    └── logs/                      # 日志文件
```

---

## 🔍 查看运行结果

### 1. 检查生成的 Fuzz Target

```bash
# 查看生成的代码
ls -lh results/output-cjson-cJSON_Parse/raw-targets/

# 查看具体文件
cat results/output-cjson-cJSON_Parse/raw-targets/target_01.c
```

### 2. 查看编译结果

```bash
# 查看状态目录
cat results/output-cjson-cJSON_Parse/status/status.txt
```

### 3. 查看覆盖率报告

```bash
# 查看覆盖率
ls results/output-cjson-cJSON_Parse/code-coverage-reports/
```

---

## 🐛 常见问题

### 1. 认证问题

如果使用 Vertex AI，需要先设置 Google Cloud 认证：

```bash
# 设置认证
gcloud auth application-default login

# 设置项目
gcloud config set project YOUR_PROJECT_ID
```

### 2. 模型不可用

检查模型名称是否正确：

```bash
# 查看所有可用模型
python3 -c "from llm_toolkit import models; print(models.LLM.all_llm_names())"
```

### 3. 超时问题

增加超时时间：

```bash
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat \
  --run-timeout 300  # 5分钟
```

---

## 📊 Workflow 执行流程

LangGraph workflow 的执行流程：

```
1. Supervisor (路由决策)
   ↓
2. FunctionAnalyzer (分析函数)
   ↓
3. Supervisor (决定下一步)
   ↓
4. Prototyper (生成代码)
   ↓
5. Supervisor (决定下一步)
   ↓
6. Build (编译)
   ↓
7. Supervisor (决定下一步)
   ↓
8. Execution (运行)
   ↓
9. 如果有问题 → Enhancer/CrashAnalyzer
   ↓
10. 重复直到成功或达到最大迭代次数
```

---

## 🔬 高级用法

### 1. 自定义工作目录

```bash
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat \
  -w ./my-custom-results
```

### 2. 指定 OSS-Fuzz 目录

```bash
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat \
  --oss-fuzz-dir /path/to/oss-fuzz
```

### 3. 使用不同的 temperature

```bash
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat \
  --temperature 0.7
```

---

## 💡 提示

1. **首次运行**: 第一次运行会下载 OSS-Fuzz 和相关依赖，可能需要一些时间
2. **并行运行**: 避免同时运行太多实验，可能超出 LLM API 配额
3. **日志级别**: 使用 `-v` 查看详细日志，便于调试
4. **结果保存**: 所有中间结果都会保存，可以随时中断和恢复

---

## 📚 相关文档

- [LangGraph 架构评估](docs/ARCHITECTURE_ASSESSMENT.md)
- [Agent Graph README](agent_graph/README.md)
- [OSS-Fuzz 项目设置](Usage.md)
- [优化路线图](docs/OPTIMIZATION_ROADMAP.md)

---

**祝测试顺利！** 🎉

如有问题，请查看日志文件或联系开发团队。

