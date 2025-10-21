# 快速开始指南 - LangGraph Workflow

## ✅ 修复完成

已成功修复 `TokenAwareSessionService` 导入错误。现在可以正常运行 LangGraph workflow。

---

## 🚀 立即开始

### 1️⃣ 最简单的测试命令

```bash
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat
```

### 2️⃣ 带详细日志的测试

```bash
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat \
  --verbose
```

### 3️⃣ 完整功能测试（带上下文）

```bash
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model gpt-5 \
  --context \
  --max-iterations 5 \
  --run-timeout 120 \
  --verbose
```

---

## 📋 可测试的函数

根据 `conti-benchmark/cjson.yaml`，可以测试的函数：

1. **cJSON_Parse** - 解析 JSON 字符串
   ```bash
   python3 agent_graph/main.py -y conti-benchmark/cjson.yaml -f cJSON_Parse --model vertex_ai_gemini-2-5-pro-chat
   ```

2. **cJSON_ParseWithLength** - 带长度参数的 JSON 解析
   ```bash
   python3 agent_graph/main.py -y conti-benchmark/cjson.yaml -f cJSON_ParseWithLength --model vertex_ai_gemini-2-5-pro-chat
   ```

---

## 🔧 可用的 LLM 模型

### Google Vertex AI (推荐)
- `vertex_ai_gemini-2-5-pro-chat` ⭐ **推荐**
- `vertex_ai_gemini-2-5-flash-chat`
- `vertex_ai_gemini-2-flash-chat`
- `vertex_ai_gemini-2-chat`

### OpenAI
- `gpt-4o`
- `gpt-4-turbo`
- `gpt-5-chat`

### Claude (via Vertex AI)
- `vertex_ai_claude-3-5-sonnet`
- `vertex_ai_claude-3-opus`

---

## 📊 验证运行结果

### 检查输出目录

```bash
# 查看生成的目录
ls -lh results/

# 查看最新的输出
ls -lh results/output-cjson-*/
```

### 查看生成的代码

```bash
# 查看生成的 fuzz targets
find results -name "*.c" -type f

# 查看具体的代码
cat results/output-cjson-*/raw-targets/target_01.c
```

### 检查运行状态

```bash
# 查看状态文件
cat results/output-cjson-*/status/status.txt
```

---

## 🐛 故障排除

### 问题 1: Google Cloud 认证错误

```bash
# 设置认证
gcloud auth application-default login

# 设置项目
gcloud config set project YOUR_PROJECT_ID
```

### 问题 2: 模块导入错误

```bash
# 确认虚拟环境已激活
source .venv/bin/activate

# 重新安装依赖
pip install -r requirements.txt
```

### 问题 3: OSS-Fuzz 相关错误

```bash
# 清理并重新克隆 OSS-Fuzz
rm -rf /tmp/oss-fuzz-*
# 重新运行
```

---

## 📈 预期的运行流程

运行时你会看到类似以下的输出：

```
2025-10-21 21:00:00 [INFO] main: === LangGraph Fuzzing Workflow ===
2025-10-21 21:00:00 [INFO] main: Benchmark: conti-benchmark/cjson.yaml
2025-10-21 21:00:00 [INFO] main: Function: cJSON_Parse
2025-10-21 21:00:00 [INFO] main: Model: vertex_ai_gemini-2-5-pro-chat
2025-10-21 21:00:01 [INFO] main: ✅ Loaded benchmark: cjson (cJSON_Parse)
2025-10-21 21:00:02 [INFO] main: ✅ LLM setup complete: vertex_ai_gemini-2-5-pro-chat
2025-10-21 21:00:02 [INFO] main: ✅ Workflow created
2025-10-21 21:00:02 [INFO] main: 🚀 Starting full workflow...
2025-10-21 21:00:03 [INFO] supervisor: Starting supervisor with workflow_type=full
2025-10-21 21:00:05 [INFO] function_analyzer: Analyzing function cJSON_Parse...
...
2025-10-21 21:05:00 [INFO] main: 🎉 Workflow completed successfully!
```

---

## 💡 下一步

1. **查看详细文档**
   - [RUN_LANGGRAPH.md](RUN_LANGGRAPH.md) - 完整使用文档
   - [agent_graph/README.md](agent_graph/README.md) - 架构说明

2. **测试其他项目**
   - 查看 `conti-benchmark/` 目录中的其他 YAML 文件
   - 创建自己的 benchmark 配置

3. **优化配置**
   - 调整 `--max-iterations` 来控制迭代次数
   - 使用 `--context` 来提供更多上下文信息
   - 尝试不同的 LLM 模型

---

## ✨ 快速验证脚本

想要一键测试？运行：

```bash
# 快速测试（无交互）
python3 agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model vertex_ai_gemini-2-5-pro-chat \
  --verbose 2>&1 | tee test_run.log
```

这会：
- 运行完整的 workflow
- 将所有输出保存到 `test_run.log`
- 同时在终端显示进度

---

**祝测试顺利！** 🎉

如有问题，请查看详细日志或参考 [RUN_LANGGRAPH.md](RUN_LANGGRAPH.md)。

