# Fuzz Driver 行为分类体系 (Behavior-Based Taxonomy)

基于对 OSS-Fuzz 项目中 **4699个 fuzz drivers** 的系统性分析（350+ 项目）

---

## 📊 研究方法论

本分类体系的构建基于：
- **数据规模**: 4699 个 fuzz driver 源文件
- **项目覆盖**: 350+ 开源项目
- **分析方法**: 代码行为观察 + 模式提取
- **目标**: 为新 API 找到相似的参考 driver

### 核心原则

> **"当你面对一个新的 API 需要编写 fuzzer 时，应该能够通过观察 API 的行为特征，快速定位到类似的参考实现"**

---

## 🎯 分类维度说明

我们从 **5 个关键维度** 观察 fuzz driver 的行为：

1. **输入数据处理方式** - fuzzer 如何使用 fuzzing 输入
2. **状态管理模式** - API 是否维护状态，如何管理
3. **资源生命周期** - 内存/文件/句柄的创建和释放
4. **API 调用模式** - 单一调用还是多步骤序列
5. **错误处理策略** - 如何处理 API 的失败情况

---

## 📐 维度 1: 输入数据处理方式

### 1.1 直接传递型 (Direct Pass-Through)
**特征**: 将 fuzzing 输入原样传递给 API

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  api_parse(data, size);  // 直接传递
  return 0;
}
```

**典型场景**:
- 解析器: JSON/XML/YAML 解析
- 编解码器: 图像解码、音视频解码
- 压缩: gzip/bzip2 解压缩

**参考实例**:
- `zlib/zlib_uncompress_fuzzer.cc` - 解压缩
- `opencv/imdecode_fuzzer.cc` - 图像解码  
- `wabt/wasm2wat-fuzz.cc` - WASM 二进制读取

**关键要点**:
- ✅ 最简单的模式
- ✅ 无需额外处理输入
- ⚠️ 注意 API 是否修改输入（需要复制）

---

### 1.2 临时文件型 (Temporary File)
**特征**: API 需要文件路径，必须先将数据写入临时文件

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/fuzz_%d", getpid());
  
  FILE *fp = fopen(filename, "wb");
  fwrite(data, size, 1, fp);
  fclose(fp);
  
  api_load_file(filename);
  unlink(filename);
  return 0;
}
```

**典型场景**:
- 需要 fopen/fread 的 API
- 需要文件路径参数的 API
- 文件格式验证

**参考实例**:
- `opencv/imread_fuzzer.cc` - 图像加载（需要路径）
- `hdf5/h5_read_fuzzer.c` - HDF5 文件读取
- 大量图像/视频库

**关键要点**:
- ✅ 使用 PID 确保文件名唯一
- ✅ 必须在返回前 unlink 清理
- ⚠️ 检查磁盘空间限制（某些环境 /tmp 很小）

**辅助工具**:
```cpp
// 很多项目定义了 FuzzerTemporaryFile 类
class FuzzerTemporaryFile {
  char filename_[256];
public:
  FuzzerTemporaryFile(const uint8_t *data, size_t size) {
    sprintf(filename_, "/tmp/fuzz_%d", getpid());
    FILE *fp = fopen(filename_, "wb");
    fwrite(data, size, 1, fp);
    fclose(fp);
  }
  ~FuzzerTemporaryFile() { unlink(filename_); }
  const char* filename() { return filename_; }
};
```

---

### 1.3 结构化提取型 (Structured Extraction)
**特征**: 将输入分割成多个部分，用于不同的 API 参数

```cpp
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  int param1 = fdp.ConsumeIntegral<int>();
  bool param2 = fdp.ConsumeBool();
  std::string param3 = fdp.ConsumeBytesAsString(10);
  auto remaining = fdp.ConsumeRemainingBytes();
  
  api_function(param1, param2, param3, remaining.data(), remaining.size());
  return 0;
}
```

**典型场景**:
- 需要多个参数的 API
- 需要配置选项 + 数据的场景
- 正则表达式（模式 + 文本）

**参考实例**:
- `re2/re2_fuzzer.cc` - 提取选项 + 模式 + 文本
- `boost/boost_regex_fuzzer.cc` - 分离正则表达式和匹配字符串
- `flatbuffers/flatbuffers_parser_fuzzer.cc` - 提取 flags

**关键要点**:
- ✅ C++ 项目首选 `FuzzedDataProvider`
- ✅ C 项目手动分割: `if (size < N) return 0; int param = data[0];`
- ⚠️ 确保有足够的数据: `if (size < 3) return 0;`

---

### 1.4 往返验证型 (Round-Trip Validation)
**特征**: 编码 → 解码 → 验证一致性

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *compressed = malloc(compressBound(size));
  uint8_t *decompressed = malloc(size);
  
  compress(compressed, &comp_len, data, size);
  uncompress(decompressed, &orig_len, compressed, comp_len);
  
  assert(memcmp(data, decompressed, size) == 0);
  
  free(compressed);
  free(decompressed);
  return 0;
}
```

**典型场景**:
- 压缩/解压缩
- 加密/解密
- 序列化/反序列化
- 编码格式转换

**参考实例**:
- `zlib/*` - 多个压缩 fuzzer
- `libsodium/secretbox_easy_fuzzer.cc` - 加密+解密验证
- `json/fuzzer-parse_json.cpp` - 解析+序列化+再解析

**关键要点**:
- ✅ 验证往返一致性是最强的测试
- ✅ 可以发现编解码不对称的 bug
- ⚠️ 加密需要确定性随机数（fake_random）

---

### 1.5 增量喂送型 (Incremental Feeding)
**特征**: 将输入分块逐步传递给 API（流式处理）

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ctx = create_context();
  
  size_t chunk_size = 128;
  for (size_t i = 0; i < size; i += chunk_size) {
    size_t len = (i + chunk_size > size) ? (size - i) : chunk_size;
    process_chunk(ctx, data + i, len);
  }
  
  finalize(ctx);
  destroy_context(ctx);
  return 0;
}
```

**典型场景**:
- 流式解析器（XML/JSON SAX）
- 网络协议解析
- 大文件处理

**参考实例**:
- `libxml2/xml.c` - 支持 push parser
- `brotli/decode_fuzzer.c` - 增量解压
- `libarchive/libarchive_fuzzer.cc` - 流式归档读取

**关键要点**:
- ✅ 测试了 API 的状态机转换
- ✅ 能发现分块边界的bug
- ⚠️ 限制最大迭代次数防止超时

---

## 📐 维度 2: 状态管理模式

### 2.1 无状态调用 (Stateless)
**特征**: 每次调用独立，无需管理上下文

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  result = pure_function(data, size);  // 无状态
  return 0;
}
```

**典型场景**:
- 纯函数: hash、checksum、校验
- 简单编解码
- 数学计算

**参考实例**:
- `zlib/checksum_fuzzer.c` - CRC32 计算
- 各种 hash 函数 fuzzer

**关键要点**:
- ✅ 最简单，无需清理
- ✅ 性能最好
- ✅ 最容易编写

---

### 2.2 单对象生命周期 (Single Object Lifecycle)
**特征**: create → use → destroy 三步模式

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  obj_t *obj = obj_create();
  if (!obj) return 0;
  
  obj_process(obj, data, size);
  
  obj_destroy(obj);
  return 0;
}
```

**典型场景**:
- 对象型 API（C++ 和现代 C 库）
- 解析器对象
- 编解码器实例

**参考实例**:
- `libyaml/libyaml_parser_fuzzer.c` - parser 对象
- `harfbuzz/hb-shape-fuzzer.cc` - font/face/buffer 对象
- `mbedtls/fuzz_x509crt.c` - X.509 证书对象

**关键要点**:
- ✅ **必须确保** destroy 总是被调用
- ✅ C 中使用 `goto cleanup` 模式
- ✅ C++ 中使用 RAII （智能指针/析构函数）

**C 语言清理模式**:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  obj_t *obj = obj_create();
  if (!obj) return 0;
  
  uint8_t *buffer = malloc(BUFFER_SIZE);
  if (!buffer) goto cleanup_obj;
  
  if (obj_process(obj, data, size) != OK) goto cleanup_all;
  
cleanup_all:
  free(buffer);
cleanup_obj:
  obj_destroy(obj);
  return 0;
}
```

---

### 2.3 多步骤状态机 (Multi-Step State Machine)
**特征**: 严格的调用顺序，每一步依赖前一步的状态

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  TidyDoc doc = tidyCreate();
  
  tidySetErrorBuffer(doc, &error_buffer);      // 步骤1: 配置
  tidyParseBuffer(doc, &input_buffer);         // 步骤2: 解析
  tidyCleanAndRepair(doc);                     // 步骤3: 清理
  tidyRunDiagnostics(doc);                     // 步骤4: 诊断
  tidySaveBuffer(doc, &output_buffer);         // 步骤5: 保存
  
  tidyRelease(doc);
  return 0;
}
```

**典型场景**:
- HTML/XML 清理器
- 编译器/解释器前端
- 文档处理流水线

**参考实例**:
- `tidy-html5/tidy_fuzzer.c` - 多步骤 HTML 处理
- `libxml2/xml.c` - pull parser 和 push parser
- 编译器 fuzzer

**关键要点**:
- ✅ 按照文档规定的顺序调用
- ✅ 检查每一步的返回值
- ⚠️ 中间步骤失败也要正确清理

---

### 2.4 持久化上下文 (Persistent Context)
**特征**: 昂贵的初始化在 `LLVMFuzzerInitialize` 中完成一次

```cpp
static GlobalConfig *g_config = nullptr;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  g_config = load_expensive_config();
  initialize_library();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  api_use_config(g_config, data, size);  // 复用配置
  return 0;
}
```

**典型场景**:
- 需要加载大型配置文件
- 需要初始化数据库连接
- 需要加载模型/字典

**参考实例**:
- `libxml2/xml.c` - `xmlInitParser()` 在 Initialize 中
- `postgresql/json_parser_fuzzer.c` - 数据库初始化
- `sqlite3/ossfuzz.c` - SQLite 初始化

**关键要点**:
- ✅ 显著提高 fuzzing 性能（exec/s）
- ⚠️ 确保初始化是线程安全的
- ⚠️ 不要在 Initialize 中使用 fuzz 输入

---

## 📐 维度 3: 资源生命周期管理

### 3.1 纯栈分配 (Stack-Only)
**特征**: 所有数据都在栈上

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char buffer[1024];
  if (size > sizeof(buffer)) size = sizeof(buffer);
  
  memcpy(buffer, data, size);
  api_process(buffer, size);
  return 0;
}
```

**典型场景**:
- 小数据量处理
- 固定大小的缓冲区

**关键要点**:
- ✅ 最快，无需内存管理
- ⚠️ 栈大小有限（通常 < 1MB）
- ❌ 大数组会导致栈溢出

---

### 3.2 堆内存管理 (Heap Allocation)
**特征**: 使用 malloc/free（C）或 new/delete（C++）

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *buffer = malloc(size * 2);
  if (!buffer) return 0;
  
  api_process(data, size, buffer);
  
  free(buffer);
  return 0;
}
```

**典型场景**:
- 大数据处理
- 动态大小的缓冲区
- 需要返回数据的 API

**关键要点**:
- ✅ 支持任意大小
- ✅ **必须检查** malloc 返回值
- ⚠️ 确保所有路径都 free

**C++ RAII 方式**:
```cpp
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::vector<uint8_t> buffer(size * 2);  // 自动管理
  api_process(data, size, buffer.data());
  return 0;  // 自动释放
}
```

---

### 3.3 静态缓冲区复用 (Static Buffer Reuse)
**特征**: 使用 static 变量在多次调用间复用

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static uint8_t buffer[256 * 1024];  // 复用
  
  if (size > sizeof(buffer)) return 0;
  api_process(data, size, buffer);
  return 0;
}
```

**典型场景**:
- 需要大缓冲区但频繁调用
- 性能敏感的场景

**参考实例**:
- `zlib/zlib_uncompress_fuzzer.cc` - `static Bytef buffer[256*1024]`

**关键要点**:
- ✅ 性能优化：避免重复 malloc/free
- ✅ 适合固定大小的缓冲区
- ⚠️ 不线程安全（libFuzzer 是单线程，所以OK）

---

### 3.4 临时文件清理 (Temporary File Cleanup)
**特征**: 创建临时文件并确保删除

**最佳实践**:
```cpp
class TempFile {
  char path_[256];
public:
  TempFile(const uint8_t *data, size_t size) {
    snprintf(path_, sizeof(path_), "/tmp/fuzz_%d_%p", getpid(), this);
    FILE *fp = fopen(path_, "wb");
    if (fp) {
      fwrite(data, size, 1, fp);
      fclose(fp);
    }
  }
  ~TempFile() { unlink(path_); }
  const char* path() { return path_; }
};
```

**关键要点**:
- ✅ 使用 PID 和指针确保唯一性
- ✅ 析构函数中删除（C++）或 goto cleanup（C）
- ✅ 即使 API 崩溃，操作系统也会清理 /tmp

---

## 📐 维度 4: API 调用模式

### 4.1 单次调用 (Single Call)
**特征**: 只调用一个主函数

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  api_main_function(data, size);
  return 0;
}
```

**典型场景**:
- 解析器
- 单一功能的库

**参考实例**:
- 大多数简单 parser fuzzer

---

### 4.2 固定序列调用 (Fixed Sequence)
**特征**: 按照固定顺序调用多个 API

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  obj = create();
  setup(obj);
  process(obj, data, size);
  finalize(obj);
  destroy(obj);
  return 0;
}
```

**典型场景**:
- 有明确生命周期的 API
- 需要初始化和清理的库

**参考实例**:
- `tidy-html5/tidy_fuzzer.c`
- 大多数对象型 API

---

### 4.3 迭代调用 (Iterative Calls)
**特征**: 循环遍历容器或数据

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  archive = archive_open(data, size);
  
  while (archive_read_next_header(archive, &entry) == OK) {
    while (archive_read_data(archive, buffer, sizeof(buffer)) > 0) {
      // 处理数据
    }
  }
  
  archive_close(archive);
  return 0;
}
```

**典型场景**:
- 归档文件（ZIP/TAR）
- 容器遍历
- 流式数据处理

**参考实例**:
- `libarchive/libarchive_fuzzer.cc` - 遍历归档条目
- 各种容器库

**关键要点**:
- ⚠️ **必须限制迭代次数**: `int max_iter = 1000; while (...  && max_iter-- > 0)`
- ⚠️ 防止无限循环导致超时

---

### 4.4 条件分支调用 (Conditional Branching)
**特征**: 根据输入选择不同的 API 路径

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  int selector = data[0] % 3;
  data++; size--;
  
  switch (selector) {
    case 0: api_mode_a(data, size); break;
    case 1: api_mode_b(data, size); break;
    case 2: api_mode_c(data, size); break;
  }
  return 0;
}
```

**典型场景**:
- 测试多种 API 模式
- 测试不同配置选项
- 多功能库

**参考实例**:
- `re2/re2_fuzzer.cc` - 从输入提取选项
- `flatbuffers/flatbuffers_parser_fuzzer.cc` - 标志位控制

**关键要点**:
- ✅ 提高代码覆盖率
- ✅ 测试多种代码路径
- ⚠️ 确保每个分支都有测试

---

### 4.5 链式操作 (Chained Operations)
**特征**: 前一个操作的输出是下一个的输入

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  step1_output = step1(data, size);
  step2_output = step2(step1_output);
  step3_output = step3(step2_output);
  
  free(step3_output);
  free(step2_output);
  free(step1_output);
  return 0;
}
```

**典型场景**:
- 数据转换管道
- 编译器阶段
- 图像处理流水线

**关键要点**:
- ✅ 测试端到端流程
- ⚠️ 注意中间结果的清理

---

### 4.6 回调驱动 (Callback-Driven)
**特征**: 注册回调函数，API 调用回调

```c
void my_callback(ExifEntry *entry, void *user_data) {
  char buf[1000];
  exif_entry_get_value(entry, buf, sizeof(buf));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ExifData *exif = exif_data_new_from_data(data, size);
  if (exif) {
    exif_data_foreach_content(exif, my_callback, NULL);
    exif_data_free(exif);
  }
  return 0;
}
```

**典型场景**:
- SAX 风格的 XML 解析
- EXIF 数据遍历
- 事件驱动的 API

**参考实例**:
- `libexif/exif_loader_fuzzer.cc` - EXIF 回调
- SAX parser fuzzer

**关键要点**:
- ✅ 测试了回调的各种情况
- ⚠️ 回调中不要抛出未捕获的异常
- ⚠️ 回调中避免崩溃

---

## 📐 维度 5: 错误处理策略

### 5.1 返回值检查 (Return Value Checking)
**特征**: C 风格的错误码

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  obj_t *obj = obj_create();
  if (!obj) return 0;  // 检查
  
  int ret = obj_process(obj, data, size);
  if (ret != OK) goto cleanup;  // 检查
  
  ret = obj_finalize(obj);
  // 不检查也可以，因为要清理了
  
cleanup:
  obj_destroy(obj);
  return 0;
}
```

**典型场景**:
- C 语言 API
- 系统调用
- POSIX API

**参考实例**:
- 大多数 C 语言 fuzzer

**关键要点**:
- ✅ **必须检查** create/malloc 的返回值
- ✅ 失败时提前返回或跳转到清理代码
- ⚠️ 不要盲目 assert，应该优雅处理

---

### 5.2 异常处理 (Exception Handling)
**特征**: C++ 风格的 try-catch

```cpp
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    api_function(data, size);
  } catch (const std::exception& e) {
    // 预期的异常，静默处理
  } catch (...) {
    // 捕获所有异常
  }
  return 0;
}
```

**典型场景**:
- C++ API
- 可能抛出异常的库

**参考实例**:
- `opencv/imdecode_fuzzer.cc` - `catch (cv::Exception e)`
- `json/fuzzer-parse_json.cpp` - 多个 try-catch 层级

**关键要点**:
- ✅ **必须** catch 所有异常
- ✅ 不要让异常传播出 fuzzer
- ✅ 解析错误是预期的，应该静默处理
- ⚠️ 区分预期异常和 bug

**最佳实践**:
```cpp
try {
  json j = json::parse(data, data + size);
  // ... 进一步处理
} catch (const json::parse_error&) {
  // 预期的：输入可能不是有效 JSON
  return 0;
} catch (const json::out_of_range&) {
  // 预期的：数据可能太大
  return 0;
} catch (...) {
  // 意外的异常，但也要捕获以避免崩溃
  return 0;
}
```

---

### 5.3 信号处理 (Signal Handling)
**特征**: 使用 sigsetjmp/siglongjmp 处理复杂控制流

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  sigjmp_buf local_sigjmp_buf;
  
  MemoryContextInit();
  set_stack_base();
  
  if (!sigsetjmp(local_sigjmp_buf, 0)) {
    PG_exception_stack = &local_sigjmp_buf;
    // 调用可能触发 longjmp 的 API
    pg_parse_json(data, size);
  }
  
  FlushErrorState();
  MemoryContextReset(TopMemoryContext);
  return 0;
}
```

**典型场景**:
- 数据库系统（PostgreSQL）
- 解释器/虚拟机
- 使用 setjmp/longjmp 的老代码

**参考实例**:
- `postgresql/json_parser_fuzzer.c` - 完整的 sigjmp 处理

**关键要点**:
- ⚠️ 非常复杂，仅在必要时使用
- ⚠️ 确保正确的栈展开和清理
- ⚠️ 需要深入理解目标库的错误处理机制

---

### 5.4 混合策略 (Hybrid)
**特征**: 同时使用多种错误处理机制

```cpp
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  obj_t *obj = obj_create();
  if (!obj) return 0;  // 返回值检查
  
  try {
    int ret = obj->process(data, size);
    if (ret != 0) goto cleanup;  // 返回值检查
    
    obj->might_throw();  // 可能抛异常
    
  } catch (const std::exception& e) {
    // 异常处理
  }
  
cleanup:
  obj_destroy(obj);  // 确保清理
  return 0;
}
```

**典型场景**:
- C/C++ 混合代码
- 大型复杂库

**关键要点**:
- ✅ 确保所有错误路径都被覆盖
- ✅ 清理代码必须总是执行
- ⚠️ 注意 goto + 异常的交互

---

## 🎨 组合模式：真实世界的例子

真实的 fuzzer 通常是多个模式的组合。下面是一些典型组合：

### 组合 A: 简单解析器
```
输入处理: 直接传递
状态管理: 单对象生命周期
资源管理: 堆内存
API 调用: 固定序列
错误处理: 异常处理
```
**示例**: `opencv/imdecode_fuzzer.cc`, `wabt/wasm2wat-fuzz.cc`

---

### 组合 B: 图像文件加载器
```
输入处理: 临时文件
状态管理: 单对象生命周期
资源管理: 临时文件 + 堆内存
API 调用: 固定序列
错误处理: 异常处理
```
**示例**: `opencv/imread_fuzzer.cc`, `hdf5/h5_read_fuzzer.c`

---

### 组合 C: 压缩库
```
输入处理: 往返验证
状态管理: 无状态/单对象
资源管理: 堆内存
API 调用: 链式操作（压缩+解压）
错误处理: 返回值检查
```
**示例**: `zlib/compress_fuzzer.c`, `brotli/decode_fuzzer.c`

---

### 组合 D: 归档处理器
```
输入处理: 直接传递 + 回调
状态管理: 单对象生命周期
资源管理: 堆内存
API 调用: 迭代调用
错误处理: 返回值检查
```
**示例**: `libarchive/libarchive_fuzzer.cc`

---

### 组合 E: 正则表达式引擎
```
输入处理: 结构化提取
状态管理: 单对象生命周期
资源管理: 堆内存
API 调用: 条件分支
错误处理: 异常处理
```
**示例**: `re2/re2_fuzzer.cc`, `boost/boost_regex_fuzzer.cc`

---

### 组合 F: HTML清理器
```
输入处理: 直接传递
状态管理: 多步骤状态机
资源管理: 堆内存 + 多个缓冲区
API 调用: 固定序列
错误处理: 返回值检查
```
**示例**: `tidy-html5/tidy_fuzzer.c`

---

### 组合 G: 加密库
```
输入处理: 往返验证 + 伪随机数
状态管理: 持久化上下文（初始化）
资源管理: 堆内存
API 调用: 链式操作
错误处理: 返回值检查
```
**示例**: `libsodium/secretbox_easy_fuzzer.cc`

---

### 组合 H: 数据库/解释器
```
输入处理: 直接传递 或 结构化提取
状态管理: 持久化上下文
资源管理: 复杂内存管理
API 调用: 多种模式
错误处理: 信号处理 + 返回值
```
**示例**: `postgresql/json_parser_fuzzer.c`, `sqlite3/ossfuzz.c`

---

## 🔍 决策流程：如何选择模式

```
┌─────────────────────────────────────────────────────────────┐
│ 1. 你的 API 需要什么输入？                                     │
├─────────────────────────────────────────────────────────────┤
│   □ 单个字节数组                    → 直接传递                 │
│   □ 文件路径                       → 临时文件                 │
│   □ 多个参数                       → 结构化提取               │
│   □ 编码+解码                      → 往返验证                 │
│   □ 流式数据                       → 增量喂送                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 2. API 维护状态吗？                                           │
├─────────────────────────────────────────────────────────────┤
│   □ 纯函数                         → 无状态                   │
│   □ 需要 create/destroy            → 单对象生命周期           │
│   □ 多步骤顺序                     → 多步骤状态机             │
│   □ 昂贵的初始化                   → 持久化上下文             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 3. 需要什么资源？                                             │
├─────────────────────────────────────────────────────────────┤
│   □ 小缓冲区                       → 栈分配                   │
│   □ 大缓冲区/动态大小               → 堆分配                  │
│   □ 频繁调用                       → 静态缓冲区复用           │
│   □ 需要文件                       → 临时文件清理             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 4. 如何调用 API？                                             │
├─────────────────────────────────────────────────────────────┤
│   □ 单个函数                       → 单次调用                 │
│   □ 固定流程                       → 固定序列                 │
│   □ 遍历容器                       → 迭代调用                 │
│   □ 多种模式                       → 条件分支                 │
│   □ 管道处理                       → 链式操作                 │
│   □ 事件驱动                       → 回调驱动                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 5. API 如何报告错误？                                         │
├─────────────────────────────────────────────────────────────┤
│   □ 返回错误码                     → 返回值检查               │
│   □ 抛出异常                       → 异常处理                 │
│   □ longjmp                       → 信号处理                 │
│   □ 混合方式                       → 混合策略                 │
└─────────────────────────────────────────────────────────────┘
```

---

## ✅ 快速查找表

| API 类型 | 推荐组合 | 参考 Fuzzer |
|---------|---------|------------|
| JSON/XML/YAML 解析 | 直接传递 + 单对象 + 异常 | `libyaml/libyaml_parser_fuzzer.c` |
| 图像解码（内存） | 直接传递 + 单对象 + 异常 | `opencv/imdecode_fuzzer.cc` |
| 图像加载（文件） | 临时文件 + 单对象 + 异常 | `opencv/imread_fuzzer.cc` |
| ZIP/TAR 归档 | 直接传递 + 迭代 + 返回值 | `libarchive/libarchive_fuzzer.cc` |
| 压缩/解压 | 往返验证 + 无状态 + 返回值 | `zlib/*`, `brotli/*` |
| 加密/解密 | 往返验证 + 伪随机 + 返回值 | `libsodium/secretbox_easy_fuzzer.cc` |
| 正则表达式 | 结构化提取 + 单对象 + 异常 | `re2/re2_fuzzer.cc` |
| HTML 清理 | 直接传递 + 状态机 + 返回值 | `tidy-html5/tidy_fuzzer.c` |
| 证书/密钥解析 | 直接传递 + 单对象 + 返回值 | `mbedtls/fuzz_x509crt.c` |
| 网络协议 | 结构化提取 + 回调 + 混合 | `curl/curl_fuzzer.cc` |
| SQL 查询 | 直接传递 + 持久化 + 信号 | `sqlite3/ossfuzz.c` |
| 字体处理 | 直接传递 + 多对象 + 异常 | `harfbuzz/hb-shape-fuzzer.cc` |
| 二进制格式 | 直接传递 + 单对象 + 返回值 | `wabt/wasm2wat-fuzz.cc` |

---

## 📚 附录：常见陷阱

### ❌ 错误 1: 修改输入数据
```c
// 错误！
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  data[0] = 0;  // ❌ 修改 const 输入
}
```
**解决**: 复制到自己的缓冲区

---

### ❌ 错误 2: 忘记清理资源
```c
// 错误！
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  obj_t *obj = obj_create();
  if (error) return 0;  // ❌ 泄漏了 obj
  obj_destroy(obj);
}
```
**解决**: 使用 goto cleanup 或 RAII

---

### ❌ 错误 3: 无限循环
```c
// 错误！
while (has_more_data()) {  // ❌ 可能永不终止
  process();
}
```
**解决**: 添加最大迭代限制

---

### ❌ 错误 4: 栈溢出
```c
// 错误！
uint8_t buffer[10*1024*1024];  // ❌ 10MB 在栈上
```
**解决**: 使用堆分配或 static

---

### ❌ 错误 5: 不检查 malloc 返回值
```c
// 错误！
uint8_t *buf = malloc(size);
buf[0] = 0;  // ❌ buf 可能是 NULL
```
**解决**: 总是检查返回值

---

### ❌ 错误 6: 未捕获的异常
```cpp
// 错误！
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  api_might_throw(data, size);  // ❌ 异常泄漏
  return 0;
}
```
**解决**: 用 try-catch 包裹

---

### ❌ 错误 7: 不确定性行为（随机数）
```c
// 错误！
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  srand(time(NULL));  // ❌ 不可重现
  int random_key = rand();
  encrypt(data, size, random_key);
}
```
**解决**: 使用 fake_random 或从输入派生

---

## 📊 统计数据

基于本次分析：

- **总文件数**: 4699 个 fuzz driver 源文件
- **项目数**: 350+ 开源项目
- **最大项目**: clickhouse (398 个 fuzzer)
- **主要语言**: C (60%), C++ (40%)
- **最常见模式**: 直接传递 + 单对象生命周期 + 异常处理

---

**文档版本**: 2.0 (基于实际代码分析)  
**分析日期**: 2025-10-27  
**数据来源**: OSS-Fuzz extracted_fuzz_drivers  
