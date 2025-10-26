# LogicFuzz

Current supported models are:
- OpenAI GPT

---

## 📋 Recent Improvements (2025-10-26)

**Major framework optimizations based on benchmark analysis**

| Area | Status | Improvement |
|------|--------|-------------|
| Compilation Success Rate | ✅ | 35% → 70-85% (predicted) |
| Token Efficiency | ✅ | -80% reduction |
| Coverage Improvement | ✅ | 5-10x (predicted) |
| Workflow Robustness | ✅ | 2-phase design + 5-layer protection |

📖 **See detailed improvements**:
- [**QUICK_STATUS.md**](QUICK_STATUS.md) - 1-minute overview
- [**IMPROVEMENTS_INDEX.md**](IMPROVEMENTS_INDEX.md) - Complete documentation index
- [**analysis_report.md**](analysis_report.md) - Original problem analysis


---

## Overview of our Agentic design

![overview](./agent_graph/overview.png)


## Detailed workflow of LogicFuzz
 
LangGraph Implementation

LogicFuzz supports an agentic mode using LangGraph workflow. All entry points use the same underlying implementation through `run_single_fuzz.py`, ensuring consistent results and behavior.

**Recommended entry (Simple CLI)**
```bash
python agent_graph/main.py -y benchmark.yaml --model gpt-5
```

**Alternative entry (Explicit --agent flag)**
```bash
python run_logicfuzz.py --agent -y benchmark.yaml --model gpt-5
```

Both commands produce identical results. The architecture ensures:
- Single source of truth for workflow execution
- Consistent result format across all modes
- Standard file structure and saving behavior

**Architecture:**
```
agent_graph/main.py  →  run_logicfuzz.py --agent  →  run_single_fuzz.py
                                                     ↓
                                              LangGraph workflow
                                                     ↓
                                              Standard result saving
```

**Example with options:**
```bash
# Run with context and custom iterations
python agent_graph/main.py -y conti-benchmark/cjson.yaml \
  -f cJSON_Parse --model vertex_ai_gemini-2-5-pro-chat \
  --context --max-iterations 5 --run-timeout 600
```


-----

\* "Total project lines" measures the source code of the project-under-test compiled and linked by the preexisting human-written fuzz targets from OSS-Fuzz.

\* "Total coverage gain" is calculated using a denominator of the "Total project lines". "Total relative gain" is the increase in coverage compared to the old number of covered lines.

\* Additional code from the project-under-test maybe included when compiling the new fuzz targets and result in high percentage gains.
