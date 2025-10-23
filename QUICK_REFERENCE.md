# 🚀 LogicFuzz Agent Mode - Quick Reference

## 📌 Quick Commands

### Running Agent Mode

```bash
# Recommended approach (Simplified CLI)
python agent_graph/main.py -y benchmark.yaml --model gpt-5 --context

# Alternative approach (Explicit --agent flag)
python run_logicfuzz.py --agent -y benchmark.yaml --model gpt-5 --context
```

### Complete Example

```bash
# Run cJSON benchmark
python agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model gpt-5 \
  --context \
  --max-round 5 \
  --run-timeout 600
```

---

## 📁 Output Location

### Default Storage Path

⚠️ **Important**: Agent mode uses timestamped directories by default!

**Default path structure**:
- Auto-generated base directory: `./results-{YYYY-MM-DD-HH-MM}/`
- Full path: `./results-{timestamp}/output-{project}-{function}/`
- Example: `./results-2025-10-23-10-30/output-cjson-cjson_parse/`

💡 **Custom path**: Use `-w` / `--work-dir` parameter to specify a custom directory

```bash
# Custom directory with timestamp
python agent_graph/main.py -y bench.yaml --model gpt-5 \
  -w my-experiment-$(date +%Y%m%d)/

# Fixed directory (will overwrite previous results)
python run_logicfuzz.py --agent -y bench.yaml --model gpt-5 \
  -w results/
```

### Directory Structure

```
{work-dir}/output-{project}-{function}/
├── fuzz_targets/
│   ├── 00.fuzz_target         # Generated fuzz target code
│   └── 00.build_script        # Build script
├── status/
│   └── 00/
│       └── result.json        # ⭐ Main result JSON (if workflow succeeded)
├── requirements/
│   └── 00.txt                 # LLM-generated API semantic analysis
├── logs/
│   ├── build/
│   │   └── 00.fuzz_target-F0-00.log  # Build logs
│   └── run/
│       └── 00.log             # Execution logs
├── corpora/
│   └── 00.fuzz_target/        # Fuzzing corpus
├── artifacts/
│   └── 00.fuzz_target-F0-00/  # Crash artifacts
└── code-coverage-reports/
    └── 00.fuzz_target/
        └── linux/
            └── summary.json   # Code coverage report
```

⚠️ **Note**: The `status/00/result.json` file is only generated when the entire workflow completes successfully. If not found, check other log files.

---

## 🏗️ Architecture Overview

```
agent_graph/main.py → run_logicfuzz.py --agent → run_single_fuzz.py
                                                        ↓
                                                  LangGraph workflow
                                                        ↓
                                                  Standard results
```

**Key Points**: 
- ✅ All entry points use the same underlying implementation
- ✅ Consistent result format across all modes
- ✅ Single source of truth, easy maintenance

---

## 🔍 Common Parameters

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-y`, `--benchmark-yaml` | Benchmark YAML file | `-y cjson.yaml` |
| `--model` | LLM model name | `--model gpt-5` |

### Optional Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `-f`, `--function-name` | Target function name | First in YAML | `-f cJSON_Parse` |
| `--context` | Enable code context | False | `--context` |
| `-mr`, `--max-round` | Max iteration rounds | 100 | `--max-round 5` |
| `-to`, `--run-timeout` | Fuzzing timeout (seconds) | 300 | `--run-timeout 600` |
| `-n`, `--num-samples` | Number of LLM samples | 1 | `--num-samples 3` |
| `-t`, `--temperature` | LLM temperature (0-2) | 0.4 | `--temperature 0.7` |
| `-w`, `--work-dir` | Output directory | `./results-{timestamp}/` | `-w results/` |
| `--trial` | Trial number | 0 | `--trial 1` |
| `--verbose`, `-v` | Verbose logging | False | `--verbose` |

### Advanced Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-pf`, `--prompt-file` | Custom prompt file | `-pf my_prompt.txt` |
| `-afp`, `--additional-files-path` | Additional files directory | `-afp ./extras/` |
| `-of`, `--oss-fuzz-dir` | OSS-Fuzz directory | `-of ./oss-fuzz/` |
| `-e`, `--introspector-endpoint` | Fuzz Introspector API endpoint | `-e http://localhost:8080` |

---

## ✅ Validating Results

### Quick Checks

```bash
# 1. Find the latest results directory
ls -lt results-* | head -1

# 2. Check if output directory was generated
ls -d results-*/output-*

# 3. View generated fuzz target code
cat results-*/output-*/fuzz_targets/00.fuzz_target

# 4. View LLM's function analysis
cat results-*/output-*/requirements/00.txt

# 5. View build logs (Important!)
cat results-*/output-*/logs/build/*.log

# 6. View execution logs
cat results-*/output-*/logs/run/00.log
```

### Check for Success

```bash
# Method 1: Check if result.json exists
ls results-*/output-*/status/00/result.json

# Method 2: View result.json content
cat results-*/output-*/status/00/result.json | python -m json.tool

# Method 3: View coverage report
cat results-*/output-*/code-coverage-reports/*/linux/summary.json
```

⚠️ **Important Tips**: 
- If `status/00/result.json` doesn't exist, the workflow didn't complete
- First check `logs/build/*.log` for compilation errors
- Review main program output logs to understand overall execution status

---

## 📊 Understanding Results

### Key Fields in `result.json`

```json
{
  "compiles": true,              // Compilation successful
  "run_success": true,           // Execution successful
  "coverage": {
    "line": {"percent": 45.2},   // Line coverage percentage
    "function": {"percent": 60.1} // Function coverage percentage
  },
  "num_crashes": 0,              // Number of crashes found
  "iteration": 1,                // Iteration count
  "trial": 0,                    // Trial number
  "finished": true               // Workflow completed
}
```

### Success Criteria

✅ **Complete Success**:
- `compiles: true`
- `run_success: true`
- `coverage.line.percent > 0`

⚠️ **Partial Success**:
- `compiles: true` but `run_success: false` → Build succeeded but execution failed
- `num_crashes > 0` → Crashes found (potentially valuable!)

❌ **Failure**:
- `compiles: false` → Compilation failed, check build logs

---

## 🐛 Debugging Tips

### Build Failures
```bash
# View detailed build errors
cat results-*/output-*/logs/build/00.fuzz_target-F0-00.log

# Common issues:
# - Missing headers → Check project include paths
# - Linker errors → Verify library files in build.sh
# - Syntax errors → Review generated code in fuzz_targets/
```

### Execution Failures
```bash
# View execution logs
cat results-*/output-*/logs/run/00.log

# Common issues:
# - Timeout → Increase --run-timeout
# - ASAN errors → Memory management issues
# - Segfaults → Check input validation
```

### Zero Coverage
```bash
# Check coverage report
cat results-*/output-*/code-coverage-reports/00.fuzz_target/linux/summary.json

# Possible causes:
# - Fuzz target not actually calling target function
# - Incorrect input data format
# - Need more iterations (increase --max-round)
# - Build script issues preventing instrumentation
```

### General Debugging Workflow

1. **Check build logs first** - Most issues are compilation-related
2. **Verify fuzz target code** - Ensure it makes sense
3. **Review requirements.txt** - LLM's understanding of the API
4. **Enable verbose mode** - Get detailed execution traces
5. **Check OSS-Fuzz project** - Ensure project builds correctly

---

## 🎯 Best Practices

### For Better Coverage

1. **Enable context**: Always use `--context` for better API understanding
2. **Increase iterations**: Use `--max-round 10` or higher for complex targets
3. **Adjust timeout**: Give fuzzer more time with `--run-timeout 600` (10 minutes)
4. **Multiple samples**: Try `--num-samples 3` for variety

### For Faster Experimentation

1. **Reduce timeout**: Use `--run-timeout 60` for quick tests
2. **Limit rounds**: Use `--max-round 3` for initial validation
3. **Reuse OSS-Fuzz**: Specify `-of` to avoid re-downloading

### For Production Runs

1. **Use timestamped directories**: Default behavior preserves all runs
2. **Set explicit trials**: Use `--trial N` for reproducibility
3. **Monitor logs**: Check logs during execution
4. **Archive results**: Save entire results directory for analysis

---

## 🚀 Example Workflows

### Quick Test

```bash
# Fast test run (~5 minutes)
python agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model gpt-5 \
  --max-round 3 \
  --run-timeout 60 \
  --verbose
```

### Production Run

```bash
# Comprehensive analysis (~30 minutes)
python agent_graph/main.py \
  -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse \
  --model gpt-5 \
  --context \
  --max-round 10 \
  --run-timeout 600 \
  --num-samples 3 \
  -w production-run-$(date +%Y%m%d)/
```

### Batch Processing

```bash
# Process multiple benchmarks
for yaml in conti-benchmark/*.yaml; do
  python agent_graph/main.py \
    -y "$yaml" \
    --model gpt-5 \
    --context \
    --max-round 5 \
    --run-timeout 300
done
```

---

## 📚 Additional Resources

- **Main Documentation**: `README.md`
- **Detailed Usage**: `Usage.md`
- **Agent Development**: `agent_graph/README.md`
- **Tool Documentation**: `prompts/tool/`

---

## 💡 Tips and Tricks

1. **First Run**: Always use `--verbose` to understand the workflow
2. **Model Selection**: `gpt-5` is recommended for best results
3. **Debugging**: Start with small timeouts and few rounds, then scale up
4. **Context Matters**: The `--context` flag significantly improves results
5. **Check Examples**: Review existing fuzz targets in OSS-Fuzz for reference

---

## 🔧 Troubleshooting Common Issues

| Issue | Likely Cause | Solution |
|-------|--------------|----------|
| No output directory | Invalid YAML or missing project | Check benchmark YAML format |
| Build always fails | Missing dependencies | Verify OSS-Fuzz project builds |
| Zero coverage | Fuzz target not calling function | Review generated code |
| Timeout on every run | Function too slow | Increase `--run-timeout` |
| Out of memory | Large corpus or memory leak | Check ASAN logs |

---

## 🔍 CrashAnalyzer GDB Integration

### Overview

The CrashAnalyzer agent now has **complete GDB debugging support** in LangGraph mode, matching the traditional pipeline's capabilities.

### Key Features

✅ **Interactive GDB Debugging**: LLM can execute GDB commands in real-time  
✅ **Multi-round Analysis**: Iterative debugging until root cause is identified  
✅ **Tool Enforcement**: System requires GDB usage before accepting conclusions  
✅ **Automatic Container Management**: GDB environment setup and cleanup  
✅ **Hallucination Prevention**: Validates actual tool usage vs. pretended usage

### How It Works

When a crash is detected during execution:

```
1. execution_node detects crash → creates crash_info with artifact_path
2. supervisor routes to crash_analyzer_node
3. CrashAnalyzer creates GDB container and loads crash artifact
4. Multi-round interaction:
   - LLM analyzes crash and issues GDB commands
   - System executes commands and returns output
   - LLM continues debugging based on results
5. LLM provides conclusion: True (project bug) or False (driver bug)
6. Container cleanup
```

### Verification

Run the verification script to confirm GDB integration:

```bash
python3 verify_gdb_integration.py
```

Expected output: `✅ All checks passed! GDB integration is complete.`

### Log Indicators

Successful GDB usage will show in logs:

```
[CrashAnalyzer] Setting up GDB environment
[CrashAnalyzer] CRASH ANALYZER ROUND 00
<gdb command>
backtrace
</gdb command>
<gdb output>
#0  0x... in function_name ()
...
</gdb output>
[CrashAnalyzer] ----- ROUND 02 Received conclusion -----
```

### Result Format

Crash analysis result includes GDB usage verification:

```python
{
    "crash_analysis": {
        "root_cause": "Analysis and suggestions...",
        "true_bug": True,  # or False
        "severity": "high",  # or "low"
        "analyzed": True,
        "gdb_used": True   # ✅ Confirms actual GDB usage
    }
}
```
