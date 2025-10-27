# LogicFuzz 优化方案 v2.0
**基于 4,699 个 OSS-Fuzz 项目的经验总结**

---

## 🎯 核心理念修正

### 角色分工：
- **Function Analyzer**：识别 API 类型，确定生成策略
- **Prototyper**：根据识别的类型，选择模板并生成代码
- **Enhancer**：修复编译和运行时错误
- **Supervisor**：协调整体流程

---

## 📋 优化方案详解

### **1. 增强 Function Analyzer - API 类型识别与策略制定**

**目标**：让 Function Analyzer 能自动识别 API 类型，并为 Prototyper 提供明确的生成指导

#### 1.1 添加 API 类型分类能力

在 `function_analyzer_prompt.txt` 中添加：

```markdown
## API Type Classification

你需要分析目标函数并识别其属于以下哪种类型：

### 输入处理维度（Input Processing）
1. **Direct Buffer** - 直接接受内存缓冲区
   - 特征：参数包含 `(const uint8_t*, size_t)` 或 `(const char*, int)`
   - 例子：`json_parse(const char* str, size_t len)`
   
2. **File Path** - 接受文件路径
   - 特征：参数包含 `const char* filename` 或 `FILE*`
   - 例子：`image_load(const char* path)`
   
3. **Structured Input** - 需要多个不同类型参数
   - 特征：多个参数，类型不同（int, string, bool 等）
   - 例子：`process_data(int width, int height, const char* format, uint8_t* data)`

4. **Complex Object** - 需要构造复杂对象
   - 特征：参数是结构体指针或 C++ 对象
   - 例子：`handle_request(Request* req)`

### 状态管理维度（Stateful vs Stateless）
1. **Stateless** - 纯函数，无状态
   - 特征：独立调用，无需初始化/清理
   - 例子：`base64_encode(const uint8_t* in, size_t len)`

2. **Stateful with Context** - 需要上下文对象
   - 特征：有 create/init 和 destroy/cleanup 配对函数
   - 例子：`parser_create()` -> `parser_parse()` -> `parser_destroy()`

3. **Global State** - 修改全局状态
   - 特征：调用后影响全局变量
   - 例子：`set_global_config(Config* cfg)`

### 资源管理维度（Resource Management）
1. **No Allocation** - 不分配资源
2. **Local Allocation** - 函数内部自行管理
3. **Caller Responsible** - 调用者需要清理返回值
4. **Multi-step Lifecycle** - 需要显式 init/cleanup

### API 调用模式维度（API Call Pattern）
1. **Single Call** - 单次调用即可
2. **Multi-step Pipeline** - 需要多步骤调用
3. **Iterative** - 需要循环调用（如解压多个文件）
4. **Callback-based** - 需要提供回调函数

### 错误处理维度（Error Handling）
1. **Return Code** - 通过返回值表示错误
2. **Exception-based** - 抛出异常（C++）
3. **Error Parameter** - 通过输出参数返回错误
4. **Silent Failure** - 不报告错误

## Analysis Output Format

分析完成后，输出以下结构化信息：

```json
{
  "api_type": {
    "input_processing": "direct_buffer | file_path | structured | complex_object",
    "state_management": "stateless | stateful_context | global_state",
    "resource_management": "no_alloc | local_alloc | caller_responsible | lifecycle",
    "call_pattern": "single_call | multi_step | iterative | callback",
    "error_handling": "return_code | exception | error_param | silent"
  },
  "generation_strategy": {
    "use_fuzzed_data_provider": true/false,
    "need_temp_file": true/false,
    "need_context_object": true/false,
    "need_exception_handling": true/false,
    "need_resource_cleanup": true/false,
    "max_iterations": number (for iterative APIs),
    "recommended_template": "template_01_simple_parser | template_02_file_api | ..."
  },
  "critical_requirements": [
    "Must initialize X before calling",
    "Must clean up Y after calling",
    "Input size must be at least N bytes",
    "..."
  ],
  "similar_functions": [
    "List of similar functions in the project for reference"
  ]
}
```
```

#### 1.2 添加决策树

```markdown
## API Type Decision Tree

使用以下决策流程识别 API 类型：

### Step 1: 输入类型识别
```
Q1: 函数接受什么类型的输入？
├─ 包含 "filename", "path", "FILE*" → **需要临时文件**
├─ 包含 "(uint8_t*, size_t)" 或 "(char*, int)" → **直接缓冲区**
├─ 多个不同类型参数 → **结构化输入，需要 FuzzedDataProvider**
└─ 结构体/对象指针 → **复杂对象初始化**
```

### Step 2: 状态检查
```
Q2: 函数是否有状态？
├─ 存在配对的 create/destroy 函数 → **需要上下文对象**
├─ 文档提到"must call X before" → **多步骤初始化**
└─ 纯函数，无副作用 → **无状态，简单调用**
```

### Step 3: 资源管理
```
Q3: 函数如何管理资源？
├─ 返回指针需要调用者 free → **需要清理代码**
├─ 函数内部管理所有资源 → **无需额外清理**
└─ 需要显式 cleanup 函数 → **RAII 或 goto cleanup**
```

### Step 4: 推荐模板
```
基于以上分析，推荐使用：
- 无状态 + 直接缓冲区 → template_01_simple_parser
- 文件路径 API → template_02_file_api
- C++ + 异常 → template_03_image_decoder
- 压缩/解压 → template_04_compression
- 加密/解密 → template_05_encryption
- 正则表达式 → template_06_regex
- 归档文件 → template_07_archive
- 多步状态机 → template_08_state_machine
- 证书/ASN.1 → template_09_certificate
- 复杂对象 → template_10_complex_object
- 需要资源管理 → template_11_resource_lifecycle
```
```

---

### **2. 增强 Prototyper - 模板选择与代码生成**

**目标**：根据 Function Analyzer 的分析结果，选择合适的模板并生成高质量代码

#### 2.1 更新 Prototyper System Prompt

在 `prototyper_system.txt` 中添加：

```markdown
## Template-based Code Generation

你会收到 Function Analyzer 提供的 API 类型分析结果。根据推荐的模板生成代码。

### 核心原则
1. **严格遵循推荐模板** - Function Analyzer 已经分析了 API 特征
2. **不要偏离模板结构** - 模板是从 4,699 个成功案例中总结的
3. **只调整具体细节** - 函数名、参数类型等
4. **保持代码简洁** - 不添加不必要的复杂度

### 模板使用指南

当收到 `recommended_template: "template_01_simple_parser"` 时：
- 使用无状态、直接缓冲区模式
- 简单调用 `target_function(data, size)`
- 基本错误检查即可

当收到 `recommended_template: "template_02_file_api"` 时：
- 创建临时文件 `/tmp/fuzz_input_<pid>`
- 写入 fuzzer 数据
- 调用 API 后立即 `unlink()`

当收到 `need_fuzzed_data_provider: true` 时：
- 包含 `<fuzzer/FuzzedDataProvider.h>`
- 使用 `FuzzedDataProvider fdp(data, size)`
- 按顺序提取参数：`fdp.ConsumeIntegral<int>()`

当收到 `need_exception_handling: true` 时：
- 使用 `try-catch` 包裹所有调用
- 返回 0（不要传播异常到 fuzzer）

当收到 `need_resource_cleanup: true` 时：
- C 代码使用 `goto cleanup` 模式
- C++ 代码使用 RAII（`std::unique_ptr`, `std::vector`）
```

#### 2.2 添加模板引用

在 `prototyper_prompt.txt` 中添加完整的代码模板作为参考：

```markdown
## Code Templates Reference

### Template 01: Simple Parser (Stateless, Direct Buffer)
```c
#include <stdint.h>
#include <stddef.h>
#include "target_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  // Direct call to stateless parsing function
  target_function(data, size);
  
  return 0;
}
```

### Template 02: File-based API
```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include "target_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  char filename[256];
  snprintf(filename, sizeof(filename), "/tmp/fuzz_input_%d", getpid());
  
  FILE *fp = fopen(filename, "wb");
  if (!fp) return 0;
  fwrite(data, 1, size, fp);
  fclose(fp);
  
  // Call API with file path
  target_function(filename);
  
  unlink(filename);
  return 0;
}
```

### Template 03: C++ with Exception Handling
```cpp
#include <stdint.h>
#include <stddef.h>
#include "target_header.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    // Call target function
    target_function(data, size);
  } catch (...) {
    // Catch all exceptions to prevent fuzzer from crashing
  }
  return 0;
}
```

### Template 04: FuzzedDataProvider for Multiple Parameters
```cpp
#include <stdint.h>
#include <stddef.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "target_header.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  // Extract parameters in order
  int param1 = fdp.ConsumeIntegral<int>();
  std::string param2 = fdp.ConsumeRandomLengthString(100);
  std::vector<uint8_t> param3 = fdp.ConsumeRemainingBytes<uint8_t>();
  
  if (param3.empty()) return 0;
  
  try {
    target_function(param1, param2.c_str(), param3.data(), param3.size());
  } catch (...) {}
  
  return 0;
}
```

### Template 05: Resource Lifecycle (C)
```c
#include <stdint.h>
#include <stddef.h>
#include "target_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  // Initialize context
  context_t *ctx = context_create();
  if (!ctx) return 0;
  
  // Use context
  result_t *result = target_function(ctx, data, size);
  
  // Cleanup
  if (result) result_free(result);
  context_destroy(ctx);
  
  return 0;
}
```

### Template 06: Resource Lifecycle (C++ RAII)
```cpp
#include <stdint.h>
#include <stddef.h>
#include <memory>
#include "target_header.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  try {
    // Use smart pointers for automatic cleanup
    auto ctx = std::make_unique<Context>();
    auto result = ctx->process(data, size);
    // Automatic cleanup on scope exit
  } catch (...) {}
  
  return 0;
}
```

### Template 07: Iterative API (with limit)
```c
#include <stdint.h>
#include <stddef.h>
#include "target_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  archive_t *archive = archive_open(data, size);
  if (!archive) return 0;
  
  // Iterate with limit to prevent infinite loops
  const int MAX_ITERATIONS = 100;
  int count = 0;
  
  while (archive_has_next(archive) && count++ < MAX_ITERATIONS) {
    entry_t *entry = archive_next(archive);
    if (entry) {
      // Process entry
      entry_free(entry);
    }
  }
  
  archive_close(archive);
  return 0;
}
```

选择最接近你需求的模板，并根据实际函数签名调整细节。
```

---

### **3. 增强 Enhancer - 错误诊断与修复**

**目标**：快速识别错误类型，应用正确的修复策略

#### 3.1 添加错误模式库

在 `enhancer_prompt.txt` 中添加：

```markdown
## Common Error Patterns and Fixes

### 编译错误（Compilation Errors）

#### Error Pattern 1: Undefined Reference
```
错误信息: undefined reference to `function_name`
或: ld: symbol(s) not found

根因分析:
1. 函数名拼写错误
2. 需要 extern "C" 包裹
3. 函数在其他源文件中，未链接

修复策略:
1. 检查函数签名是否正确
2. C++ 代码调用 C 函数时添加:
   extern "C" {
   #include "c_header.h"
   }
3. 检查项目 BUILD.gn 或 Makefile 确认函数存在
```

#### Error Pattern 2: No Such File or Directory
```
错误信息: fatal error: header.h: No such file or directory

根因分析:
1. 头文件路径错误
2. 需要相对路径
3. 头文件不存在

修复策略:
1. 检查项目中类似 fuzzer 如何包含头文件
2. 使用项目相对路径: #include "src/module/header.h"
3. 查看 project.yaml 中的 main_repo 了解项目结构
```

#### Error Pattern 3: Type Mismatch
```
错误信息: cannot convert 'X' to 'Y'
或: incompatible types

根因分析:
1. 参数类型不匹配
2. const 修饰符缺失
3. 指针层级错误

修复策略:
1. 检查函数原型
2. 添加 const 修饰: const uint8_t* -> const char*
3. 调整指针: uint8_t* -> uint8_t**
```

### 运行时错误（Runtime Errors）

#### Error Pattern 4: Stack Buffer Overflow
```
错误信息: stack-buffer-overflow
或: SUMMARY: AddressSanitizer: stack-buffer-overflow

根因分析:
1. 在栈上分配了过大的数组
2. 访问越界

修复策略:
1. 大数组改用堆分配:
   // Before:
   uint8_t buffer[1024*1024];  // 1MB on stack - BAD
   
   // After:
   uint8_t *buffer = (uint8_t*)malloc(1024*1024);
   if (!buffer) return 0;
   // ... use buffer ...
   free(buffer);

2. 限制数组大小:
   if (size > 1024) size = 1024;
```

#### Error Pattern 5: Heap Buffer Overflow (修改输入)
```
错误信息: heap-buffer-overflow on address
调用栈: #0 in LLVMFuzzerTestOneInput

根因分析:
1. 代码直接修改了 data 指针指向的内存
2. fuzzer 的输入数据是只读的

修复策略:
// Before (直接修改输入 - WRONG):
data[0] = 0;  // ❌ Crash!

// After (复制后修改 - CORRECT):
uint8_t *copy = (uint8_t*)malloc(size);
if (!copy) return 0;
memcpy(copy, data, size);
copy[0] = 0;  // ✅ Safe
// ... use copy ...
free(copy);
```

#### Error Pattern 6: Memory Leak
```
错误信息: Direct leak of X byte(s)
或: ERROR: LeakSanitizer: detected memory leaks

根因分析:
1. malloc 后忘记 free
2. 提前 return 导致 free 未执行
3. 异常导致跳过 cleanup

修复策略 (C):
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *buffer = NULL;
  result_t *result = NULL;
  int ret = 0;
  
  buffer = malloc(size);
  if (!buffer) goto cleanup;
  
  result = process(buffer, size);
  if (!result) goto cleanup;
  
  // ... more processing ...
  
cleanup:
  if (buffer) free(buffer);
  if (result) free_result(result);
  return ret;
}

修复策略 (C++):
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    auto buffer = std::make_unique<uint8_t[]>(size);
    auto result = std::make_unique<Result>();
    // Automatic cleanup on exception or return
  } catch (...) {}
  return 0;
}
```

#### Error Pattern 7: Timeout (Infinite Loop)
```
错误信息: timeout
或: SLOW UNIT detected

根因分析:
1. 输入导致无限循环
2. 迭代次数过多
3. 复杂度爆炸

修复策略:
// Before:
while (has_more_data()) {
  process_next();  // May never end
}

// After:
const int MAX_ITERATIONS = 100;
int count = 0;
while (has_more_data() && count++ < MAX_ITERATIONS) {
  process_next();
}
```

#### Error Pattern 8: Uncaught Exception
```
错误信息: libc++abi: terminating with uncaught exception
或: terminate called after throwing

根因分析:
1. C++ 代码抛出异常但未捕获
2. fuzzer 框架不允许异常传播

修复策略:
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    // All potentially throwing code here
    risky_function(data, size);
  } catch (const std::exception& e) {
    // Log if needed, but don't crash
  } catch (...) {
    // Catch all other exceptions
  }
  return 0;
}
```

#### Error Pattern 9: Segmentation Fault (Null Pointer)
```
错误信息: SEGV on unknown address
或: segmentation fault

根因分析:
1. malloc 返回 NULL 后使用
2. 函数返回 NULL 未检查
3. 访问未初始化指针

修复策略:
// Before:
ptr = malloc(size);
ptr[0] = 0;  // ❌ May crash if malloc failed

// After:
ptr = malloc(size);
if (!ptr) return 0;  // ✅ Check before use
ptr[0] = 0;
```

#### Error Pattern 10: Non-deterministic Behavior
```
错误信息: (same input produces different coverage)

根因分析:
1. 使用了 rand(), time(), getpid() 等不确定函数
2. 未初始化的变量
3. 多线程竞争

修复策略:
// Before:
srand(time(NULL));  // ❌ Non-deterministic
int random_value = rand();

// After (derive from input):
#include <fuzzer/FuzzedDataProvider.h>
FuzzedDataProvider fdp(data, size);
int random_value = fdp.ConsumeIntegral<int>();  // ✅ Deterministic

// Or use a fixed seed:
srand(0);  // ✅ Fixed seed
```

### 修复流程

1. **识别错误类型**：根据错误信息匹配上述模式
2. **定位根因**：理解为什么会出现这个错误
3. **应用修复**：使用推荐的修复策略
4. **最小化改动**：只修改必要的部分，保持原有逻辑
5. **验证修复**：确保修复不引入新问题
```

---

### **4. 优化 Supervisor - 智能路由决策**

**目标**：根据当前状态和错误类型，智能选择下一步行动

#### 4.1 错误类型到节点的映射

在 `supervisor_node.py` 中添加智能路由逻辑：

```python
# Error pattern to next action mapping
ERROR_ROUTING_MAP = {
    # Compilation errors
    "undefined reference": "function_analyzer",  # Need to re-check function signature
    "no such file": "context_analyzer",  # Need to find correct headers
    "cannot convert": "enhancer",  # Type mismatch, need fixing
    "expected": "enhancer",  # Syntax error
    
    # Linker errors
    "ld:": "function_analyzer",  # Linker issue, may need to check symbols
    
    # Runtime errors
    "stack-buffer-overflow": "enhancer",  # Need to fix stack allocation
    "heap-buffer-overflow": "enhancer",  # Need to fix heap overflow
    "memory leak": "enhancer",  # Need to add cleanup
    "timeout": "enhancer",  # Need to add iteration limit
    "segmentation fault": "enhancer",  # Need to add null checks
    "uncaught exception": "enhancer",  # Need to add try-catch
    
    # Coverage issues
    "low coverage": "coverage_analyzer",  # Analyze why coverage is low
    
    # Crash issues
    "crash": "crash_analyzer",  # Analyze crash details
}

def route_based_on_error(state: FuzzingWorkflowState) -> str:
    """Route to appropriate node based on error pattern."""
    
    # Check if we have compilation errors
    if not state.get("compile_success", False):
        compile_log = state.get("compile_log", "")
        
        # Try to match error patterns
        for pattern, next_node in ERROR_ROUTING_MAP.items():
            if pattern in compile_log.lower():
                return next_node
        
        # Default: use enhancer for unknown compilation errors
        return "enhancer"
    
    # Check if we have runtime errors
    if state.get("run_error"):
        run_log = state.get("run_log", "")
        
        for pattern, next_node in ERROR_ROUTING_MAP.items():
            if pattern in run_log.lower():
                return next_node
        
        return "enhancer"
    
    # Check if we have low coverage
    coverage_percent = state.get("coverage_percent", 0)
    if coverage_percent < 0.3 and state.get("workflow_phase") == "optimization":
        return "coverage_analyzer"
    
    # Check if we have crashes to analyze
    if state.get("crashes") and not state.get("crash_analysis"):
        return "crash_analyzer"
    
    # Success case: terminate
    return "__end__"
```

#### 4.2 阶段化执行策略

```python
def determine_workflow_phase(state: FuzzingWorkflowState) -> str:
    """Determine current workflow phase."""
    
    compile_success = state.get("compile_success", False)
    run_success = state.get("run_success", False)
    
    if not compile_success:
        return "compilation"  # Focus on getting code to compile
    elif not run_success:
        return "runtime_fix"  # Focus on fixing runtime errors
    else:
        return "optimization"  # Focus on improving coverage

def get_next_action_by_phase(state: FuzzingWorkflowState, phase: str) -> str:
    """Get next action based on current phase."""
    
    if phase == "compilation":
        # During compilation phase, focus on:
        # 1. Function analysis (if not done)
        # 2. Code generation (if not done)
        # 3. Error fixing (if compile failed)
        
        if not state.get("function_analysis"):
            return "function_analyzer"
        
        if not state.get("fuzz_target_source"):
            return "prototyper"
        
        if not state.get("compile_success"):
            retry_count = state.get("compilation_retry_count", 0)
            if retry_count > 5:
                # Too many retries, try regenerating from scratch
                return "prototyper"
            else:
                return "enhancer"
        
        # Compilation succeeded, move to next phase
        return "build"
    
    elif phase == "runtime_fix":
        # During runtime fix phase, focus on:
        # 1. Execution
        # 2. Fixing runtime errors
        
        if not state.get("run_success"):
            return route_based_on_error(state)
        
        # Runtime working, move to optimization
        return "execution"
    
    elif phase == "optimization":
        # During optimization phase, focus on:
        # 1. Coverage analysis
        # 2. Crash analysis
        # 3. Iterative improvement
        
        coverage_percent = state.get("coverage_percent", 0)
        no_improvement_count = state.get("no_coverage_improvement_count", 0)
        
        if no_improvement_count >= 3:
            # No improvement for 3 iterations, terminate
            return "__end__"
        
        if coverage_percent < 0.5:
            return "coverage_analyzer"
        
        if state.get("crashes") and not state.get("crash_analysis"):
            return "crash_analyzer"
        
        # Good enough, terminate
        return "__end__"
    
    return "__end__"
```

---

### **5. 增强 Context Analyzer - 项目模式学习**

**目标**：从项目现有的 fuzzer 中学习模式

#### 5.1 添加模式提取功能

在 `context_analyzer_prompt.txt` 中添加：

```markdown
## Learn from Existing Fuzzers

分析项目中已有的 fuzzer，提取可复用的模式。

### 搜索位置
1. `*_fuzzer.cc`, `*_fuzzer.c`
2. `*_fuzz_test.cc`, `*_fuzz_test.c`
3. `fuzz/`, `fuzzing/`, `tests/fuzz/` 目录

### 提取内容

#### 1. Header Include Patterns
```cpp
// 记录项目如何包含头文件
#include "src/module/header.h"  // 相对路径风格
#include <project/public_api.h>  // 公开 API 风格
```

#### 2. Initialization Patterns
```cpp
// 记录项目如何初始化对象
Context* ctx = context_new();
context_set_option(ctx, OPTION_XYZ, 1);
```

#### 3. Cleanup Patterns
```cpp
// 记录项目如何清理资源
if (result) free_result(result);
context_destroy(ctx);
```

#### 4. FuzzedDataProvider Usage
```cpp
// 如果项目已经使用 FDP，学习其使用方式
FuzzedDataProvider fdp(data, size);
int param1 = fdp.ConsumeIntegral<int>();
```

#### 5. Temporary File Creation
```cpp
// 学习项目如何创建临时文件
char temp_path[PATH_MAX];
snprintf(temp_path, sizeof(temp_path), "/tmp/fuzz_%d", getpid());
```

#### 6. Exception Handling Style
```cpp
// C++ 项目的异常处理风格
try {
  // ...
} catch (const CustomException& e) {
  // ...
}
```

### Output Format

输出提取的模式供 Prototyper 参考：

```json
{
  "include_style": {
    "pattern": "#include \"src/module/header.h\"",
    "examples": [...]
  },
  "initialization_pattern": {
    "code": "Context* ctx = context_new();\ncontext_set_option(ctx, ...);\n",
    "cleanup": "context_destroy(ctx);"
  },
  "uses_fuzzed_data_provider": true,
  "temporary_file_pattern": "snprintf(path, sizeof(path), \"/tmp/fuzz_%d\", getpid());",
  "exception_handling_style": "try-catch with specific exceptions"
}
```
```

---

### **6. 创建代码模板库**

**实施方案**：创建独立的模板文件，供 prompt 引用

#### 6.1 目录结构

```
prompts/agent_graph/templates/
├── README.md                           # 模板使用指南
├── 01_simple_parser.c                  # 无状态解析器
├── 02_file_api.c                       # 文件路径 API
├── 03_image_decoder.cpp                # 图像解码（异常处理）
├── 04_compression.c                    # 压缩/解压
├── 05_encryption.c                     # 加密/解密
├── 06_regex.cpp                        # 正则表达式
├── 07_archive.cpp                      # 归档文件
├── 08_state_machine.c                  # 多步状态机
├── 09_certificate.c                    # 证书解析
├── 10_complex_object.cpp               # 复杂对象初始化
└── 11_resource_lifecycle.c             # 资源生命周期
```

#### 6.2 在 Prompt 中引用模板

在 `prompts/agent_graph/prototyper_prompt.txt` 中：

```markdown
## Available Code Templates

Based on Function Analyzer's recommendation, select the appropriate template:

- **template_01_simple_parser**: {TEMPLATE_01_CONTENT}
- **template_02_file_api**: {TEMPLATE_02_CONTENT}
- **template_03_image_decoder**: {TEMPLATE_03_CONTENT}
... (其他模板)

使用时:
1. 复制整个模板代码
2. 将 `target_function` 替换为实际函数名
3. 将 `target_header.h` 替换为实际头文件
4. 调整参数提取逻辑（如果使用 FuzzedDataProvider）
5. 调整初始化和清理代码
```

---

## 🎯 实施优先级（修正版）

### **Phase 1: 核心流程优化（立即实施，1-2 天）**
1. ✅ **Function Analyzer 增强** - 添加 API 类型识别和决策树
2. ✅ **Prototyper 模板化** - 添加模板选择逻辑
3. ✅ **Enhancer 错误诊断** - 添加常见错误模式库

### **Phase 2: 模板库建设（1 周）**
4. ✅ **创建代码模板库** - 11 个典型场景的完整代码
5. ✅ **模板集成** - 将模板嵌入 prompt 中

### **Phase 3: 智能化提升（2 周）**
6. ✅ **Context Analyzer 学习** - 从项目现有 fuzzer 学习模式
7. ✅ **Supervisor 智能路由** - 基于错误类型的路由决策

---

## 📊 预期效果

### 量化指标
- **首次编译成功率**: 40% → 70%+
- **3 轮内编译成功率**: 60% → 90%+
- **平均迭代次数**: 5-7 轮 → 3-4 轮
- **资源泄漏率**: 30% → < 5%
- **平均代码覆盖率**: +15-20%

### 质量改进
- ✅ 生成的代码更符合项目风格
- ✅ 更少的编译错误
- ✅ 更少的运行时错误
- ✅ 更好的资源管理
- ✅ 更高的代码可读性

---

## ❓ 下一步行动

请确认以下问题：

1. **优先级确认**: 是否先实施 Phase 1（Function Analyzer + Prototyper + Enhancer）？
2. **模板需求**: 是否需要为特定领域（如图像处理、音频解码等）增加专用模板？
3. **兼容性**: 现有的 benchmark 是否需要重新测试？
4. **时间安排**: 希望多久完成 Phase 1？

告诉我您的决定，我会立即开始实施！

