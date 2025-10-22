# 🚀 LogicFuzz Agent Mode - Quick Reference

## 📌 快速命令

### 运行Agent模式

```bash
# 推荐方式 (简洁CLI)
python agent_graph/main.py -y benchmark.yaml --model gpt-5 --context

# 等价方式 (显式flag)
python run_logicfuzz.py --agent -y benchmark.yaml --model gpt-5 --context
```

### 完整示例

```bash
# 运行cJSON benchmark
python agent_graph/main.py \
  -y benchmark-sets/0-conti/cjson.yaml \
  -f cJSON_Parse \
  --model gpt-5 \
  --context \
  --max-iterations 5 \
  --run-timeout 600
```

---

## 📁 结果位置

### 默认存储路径

⚠️ **重要**: Agent模式和非Agent模式使用相同的默认路径！

**默认路径结构**:
- 默认基础目录: `results/`
- 完整路径: `results/output-<project>-<function>/`
- 示例: `results/output-cjson-cjson_parse/`

💡 **自定义路径**: 使用 `-w` / `--work-dir` 参数指定带时间戳的目录

```bash
# 使用带时间戳的目录避免覆盖之前的结果
python run_logicfuzz.py --agent -y bench.yaml --model gpt-5 \
  -w results-$(date +%Y-%m-%d-%H-%M)/
```

⚠️ **注意**: `agent_graph/main.py` 当前不支持 `-w` 参数。如需自定义路径，请使用 `run_logicfuzz.py --agent`

### 目录结构

```
results/output-<project>-<function>/
├── fuzz_targets/
│   ├── 00.fuzz_target         # 生成的fuzz target代码
│   └── 00.build_script        # 构建脚本
├── status/
│   └── 00/
│       └── result.json        # ⭐ 主要结果JSON (如果生成成功)
├── requirements/
│   └── 00.txt                 # LLM生成的API语义分析
├── logs/
│   ├── build/
│   │   └── 00.fuzz_target-F0-00.log  # 构建日志
│   └── run/
│       └── 00.log             # 运行日志
├── corpora/
│   └── 00.fuzz_target/        # Fuzzing语料库
├── artifacts/
│   └── 00.fuzz_target-F0-00/  # Crash artifacts
└── code-coverage-reports/
    └── 00.fuzz_target/
        └── linux/
            └── summary.json   # 代码覆盖率报告
```

⚠️ **注意**: `status/00/result.json` 文件只在整个workflow成功完成时才会生成。如果未找到该文件，请检查其他日志文件。

---

## 🏗️ 架构一图

```
agent_graph/main.py → run_logicfuzz.py --agent → run_single_fuzz.py
                                                        ↓
                                                  LangGraph workflow
                                                        ↓
                                                  Standard results
```

**关键点**: 
- ✅ 所有入口使用相同的底层实现
- ✅ 结果格式完全一致
- ✅ 单一数据源，易维护

---

## 🔍 常用参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-y` | Benchmark YAML | `-y bench.yaml` |
| `-f` | 指定函数 | `-f func_name` |
| `--model` | LLM模型 | `--model gpt-5` |
| `--context` | 使用代码上下文 | `--context` |
| `--max-iterations` | 最大迭代次数 | `--max-iterations 5` |
| `--run-timeout` | 运行超时(秒) | `--run-timeout 600` |
| `--trial` | Trial编号 | `--trial 0` |
| `--verbose` | 详细日志 | `--verbose` |

---

## ✅ 验证结果

### 快速检查

```bash
# 1. 查找最新的结果目录
ls -lt results-* | head -1

# 2. 检查是否生成了output目录
ls -d results-*/output-*

# 3. 查看生成的fuzz target代码
cat results-*/output-*/fuzz_targets/00.fuzz_target

# 4. 查看LLM的函数分析
cat results-*/output-*/requirements/00.txt

# 5. 查看构建日志（重要！）
cat results-*/output-*/logs/build/*.log

# 6. 查看运行日志
cat results-*/output-*/logs/run/00.log
```

### 检查是否成功

```bash
# 方式1：检查 result.json 是否存在
ls results-*/output-*/status/00/result.json

# 方式2：查看 result.json 内容
cat results-*/output-*/status/00/result.json | python -m json.tool

# 方式3：查看覆盖率报告
cat results-*/output-*/code-coverage-reports/*/linux/summary.json
```

⚠️ **重要提示**: 
- 如果 `status/00/result.json` 不存在，说明workflow未完成
- 优先检查 `logs/build/*.log` 看是否有编译错误
- 查看主程序输出日志了解整体执行状态

---

## 📊 理解结果

### `result.json` 关键字段

```json
{
  "compiles": true,              // 是否编译成功
  "run_success": true,           // 是否运行成功
  "coverage": {
    "line": {"percent": 45.2},   // 行覆盖率
    "function": {"percent": 60.1} // 函数覆盖率
  },
  "num_crashes": 0,              // 发现的crash数量
  "iteration": 1,                // 迭代次数
  "trial": 0,                    // Trial编号
  "finished": true               // 是否完成
}
```

### 成功标准

✅ **完全成功**:
- `compiles: true`
- `run_success: true`
- `coverage.line.percent > 0`

⚠️ **部分成功**:
- `compiles: true` but `run_success: false` → 构建成功但运行失败
- `num_crashes > 0` → 发现了crash（可能是好事！）

❌ **失败**:
- `compiles: false` → 编译失败，检查构建日志

---

## 🐛 调试技巧

### 构建失败
```bash
# 查看详细的构建错误
cat results-*/logs/build/00.fuzz_target-F0-00.log

# 常见问题：
# - 缺少头文件 → 检查项目的include路径
# - 链接错误 → 检查build.sh中的库文件
```

### 运行失败
```bash
# 查看运行日志
cat results-*/logs/run/00.log

# 常见问题：
# - Timeout → 增加 --run-timeout
# - ASAN错误 → 检查内存管理问题
```

### 覆盖率为0
```bash
# 检查代码覆盖率报告
cat results-*/code-coverage-reports/00.fuzz_target/linux/summary.json

# 可能原因：
# - Fuzz target没有真正调用目标函数
# - 输入数据格式不正确
# - 需要更多迭代次数
```

---

## 📚 更多资源

- **完整文档**: `README.md`
- **用法详情**: `Usage.md`
- **Agent开发**: `agent_graph/README.md`

---

## 💡 提示

1. **首次运行**：使用 `--verbose` 查看详细日志
2. **提高覆盖率**：增加 `--max-iterations` 和 `--run-timeout`
3. **调试模式**：添加 `--context` 提供代码上下文
4. **批量测试**：使用 `--num-samples` 运行多个样本

---

**最后更新**: 2025-10-22  
**状态**: ✅ 生产Ready

