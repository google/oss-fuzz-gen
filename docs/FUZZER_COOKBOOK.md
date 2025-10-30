# Fuzz Driver 实战手册 (Practical Cookbook)

**基于 4699 个真实 fuzzer 的经验总结**

> 💡 本手册提供可以直接复制粘贴的代码模板和实战技巧

---

## 📋 目录

1. [按 API 类型查找模板](#按-api-类型查找模板)
2. [常见问题解决方案](#常见问题解决方案)
3. [完整代码模板](#完整代码模板)
4. [调试和优化技巧](#调试和优化技巧)

---

## 按 API 类型查找模板

### 🔹 场景 1: 简单的解析器（内存输入）

**适用于**: JSON, XML, YAML, Protobuf 等接受内存数据的解析器

```c
#include <stddef.h>
#include <stdint.h>
#include "your_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 100 * 1024) return 0;  // 限制大小
  
  parser_t *parser = parser_create();
  if (!parser) return 0;
  
  parser_parse(parser, data, size);
  
  parser_destroy(parser);
  return 0;
}
```

**参考实例**: 
- `libyaml/libyaml_parser_fuzzer.c`
- `wabt/wasm2wat-fuzz.cc`

---

### 🔹 场景 2: 需要文件路径的 API

**适用于**: imread, H5Fopen, 以及任何需要文件路径的函数

```c
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "your_api.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  // 创建唯一的临时文件名
  char filename[256];
  sprintf(filename, "/tmp/fuzz_%d", getpid());
  
  // 写入数据到临时文件
  FILE *fp = fopen(filename, "wb");
  if (!fp) return 0;
  fwrite(data, size, 1, fp);
  fclose(fp);
  
  // 调用 API
  your_api_load_file(filename);
  
  // 清理
  unlink(filename);
  return 0;
}
```

**参考实例**:
- `opencv/imread_fuzzer.cc`
- `hdf5/h5_read_fuzzer.c`

**C++ RAII 版本**:
```cpp
class TempFile {
  char path_[256];
public:
  TempFile(const uint8_t *data, size_t size) {
    snprintf(path_, sizeof(path_), "/tmp/fuzz_%d", getpid());
    FILE *fp = fopen(path_, "wb");
    if (fp) {
      fwrite(data, size, 1, fp);
      fclose(fp);
    }
  }
  ~TempFile() { unlink(path_); }
  const char* path() const { return path_; }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  TempFile tmpfile(data, size);
  your_api_load_file(tmpfile.path());
  return 0;  // 自动清理
}
```

---

### 🔹 场景 3: 图像解码（C++，异常处理）

**适用于**: OpenCV, 图像库

```cpp
#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <opencv2/opencv.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  try {
    std::vector<uint8_t> image_data(data, data + size);
    cv::Mat data_mat(1, image_data.size(), CV_8UC1, image_data.data());
    cv::Mat decoded = cv::imdecode(data_mat, cv::IMREAD_UNCHANGED);
  } catch (cv::Exception& e) {
    // 预期的异常，静默处理
  } catch (...) {
    // 捕获所有其他异常
  }
  
  return 0;
}
```

**参考实例**: `opencv/imdecode_fuzzer.cc`

---

### 🔹 场景 4: 压缩/解压（往返验证）

**适用于**: zlib, bzip2, brotli, lz4 等

```c
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 100 * 1024) return 0;
  
  // 分配压缩缓冲区
  uLongf compressed_size = compressBound(size);
  uint8_t *compressed = malloc(compressed_size);
  if (!compressed) return 0;
  
  // 分配解压缓冲区
  uLongf decompressed_size = size;
  uint8_t *decompressed = malloc(decompressed_size);
  if (!decompressed) {
    free(compressed);
    return 0;
  }
  
  // 压缩
  if (compress(compressed, &compressed_size, data, size) == Z_OK) {
    // 解压
    if (uncompress(decompressed, &decompressed_size, 
                   compressed, compressed_size) == Z_OK) {
      // 验证一致性
      assert(decompressed_size == size);
      assert(memcmp(data, decompressed, size) == 0);
    }
  }
  
  free(decompressed);
  free(compressed);
  return 0;
}
```

**参考实例**: `zlib/*`, `brotli/decode_fuzzer.c`

---

### 🔹 场景 5: 加密/解密（往返 + 伪随机数）

**适用于**: libsodium, mbedtls 等加密库

```c
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sodium.h>
#include "fake_random.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  sodium_init();
  
  // 使用输入数据初始化伪随机数生成器（确保可重现）
  setup_fake_random(data, size);
  
  // 生成密钥和nonce（确定性）
  unsigned char key[crypto_secretbox_KEYBYTES];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  crypto_secretbox_keygen(key);
  randombytes_buf(nonce, sizeof nonce);
  
  // 加密
  size_t ciphertext_len = crypto_secretbox_MACBYTES + size;
  unsigned char *ciphertext = malloc(ciphertext_len);
  if (!ciphertext) return 0;
  
  crypto_secretbox_easy(ciphertext, data, size, nonce, key);
  
  // 解密
  unsigned char *decrypted = malloc(size);
  if (!decrypted) {
    free(ciphertext);
    return 0;
  }
  
  int err = crypto_secretbox_open_easy(decrypted, ciphertext, 
                                       ciphertext_len, nonce, key);
  assert(err == 0);
  
  free(decrypted);
  free(ciphertext);
  return 0;
}
```

**参考实例**: `libsodium/secretbox_easy_fuzzer.cc`

**fake_random.h 实现** (需要自己创建):
```c
#include <stdint.h>
#include <string.h>

static const uint8_t *g_fake_random_data = NULL;
static size_t g_fake_random_size = 0;
static size_t g_fake_random_offset = 0;

void setup_fake_random(const uint8_t *data, size_t size) {
  g_fake_random_data = data;
  g_fake_random_size = size;
  g_fake_random_offset = 0;
}

void randombytes_buf(void *buf, size_t n) {
  uint8_t *dest = (uint8_t *)buf;
  for (size_t i = 0; i < n; i++) {
    dest[i] = g_fake_random_data[g_fake_random_offset % g_fake_random_size];
    g_fake_random_offset++;
  }
}
```

---

### 🔹 场景 6: 正则表达式（分离模式和输入文本）

**适用于**: RE2, boost::regex, PCRE

**C++ 版本 (使用 FuzzedDataProvider)**:
```cpp
#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include "re2/re2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;
  
  FuzzedDataProvider fdp(data, size);
  
  // 提取正则表达式模式（最多100字节）
  std::string pattern = fdp.ConsumeRandomLengthString(100);
  
  // 剩余数据作为匹配文本
  std::string text = fdp.ConsumeRemainingBytesAsString();
  
  // 尝试编译和匹配
  try {
    RE2 re(pattern);
    if (re.ok()) {
      RE2::FullMatch(text, re);
      RE2::PartialMatch(text, re);
    }
  } catch (...) {
    // 捕获所有异常
  }
  
  return 0;
}
```

**C 版本（手动分割）**:
```c
#include <stddef.h>
#include <stdint.h>
#include <boost/regex.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;
  
  // 第一个字节表示模式长度
  size_t pattern_len = data[0];
  data++; size--;
  
  if (pattern_len > size) pattern_len = size;
  
  // 提取模式
  char *pattern = malloc(pattern_len + 1);
  memcpy(pattern, data, pattern_len);
  pattern[pattern_len] = '\0';
  
  // 剩余部分是文本
  const char *text = (const char *)(data + pattern_len);
  size_t text_len = size - pattern_len;
  
  // 测试正则表达式
  try {
    boost::regex re(pattern);
    boost::regex_match(text, text + text_len, re);
  } catch (...) {}
  
  free(pattern);
  return 0;
}
```

**参考实例**: `re2/re2_fuzzer.cc`, `boost/boost_regex_fuzzer.cc`

---

### 🔹 场景 7: 归档文件（ZIP/TAR，迭代器模式）

**适用于**: libarchive, minizip

```cpp
#include <stddef.h>
#include <stdint.h>
#include <vector>
#include "archive.h"

// 自定义读取回调
ssize_t reader_callback(struct archive *a, void *client_data, 
                        const void **block) {
  struct Buffer {
    const uint8_t *buf;
    size_t len;
  } *buffer = (struct Buffer *)client_data;
  
  *block = buffer->buf;
  ssize_t len = buffer->len;
  buffer->len = 0;  // 只读一次
  return len;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct archive *a = archive_read_new();
  if (!a) return 0;
  
  archive_read_support_filter_all(a);
  archive_read_support_format_all(a);
  
  struct Buffer {
    const uint8_t *buf;
    size_t len;
  } buffer = {data, size};
  
  if (archive_read_open(a, &buffer, NULL, reader_callback, NULL) == ARCHIVE_OK) {
    std::vector<uint8_t> data_buffer(4096);
    struct archive_entry *entry;
    int max_entries = 100;  // 限制条目数
    
    while (max_entries-- > 0) {
      int ret = archive_read_next_header(a, &entry);
      if (ret == ARCHIVE_EOF || ret == ARCHIVE_FATAL) break;
      if (ret == ARCHIVE_RETRY) continue;
      
      // 读取条目数据
      ssize_t r;
      int max_reads = 1000;  // 限制读取次数
      while ((r = archive_read_data(a, data_buffer.data(), 
                                     data_buffer.size())) > 0 
             && max_reads-- > 0) {
        // 处理数据
      }
      if (r == ARCHIVE_FATAL) break;
    }
  }
  
  archive_read_free(a);
  return 0;
}
```

**关键要点**:
- ✅ 限制最大条目数（防止zip bomb）
- ✅ 限制每个条目的读取次数
- ✅ 检查 ARCHIVE_FATAL 并中断

**参考实例**: `libarchive/libarchive_fuzzer.cc`

---

### 🔹 场景 8: HTML/XML 清理器（多步骤状态机）

**适用于**: tidy-html5, 文档处理器

```c
#include <stddef.h>
#include <stdint.h>
#include "tidy.h"
#include "tidybuffio.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  TidyBuffer input_buffer, output_buffer, error_buffer;
  tidyBufInit(&input_buffer);
  tidyBufInit(&output_buffer);
  tidyBufInit(&error_buffer);
  
  // 附加输入数据
  tidyBufAttach(&input_buffer, (byte *)data, size);
  
  // 创建文档
  TidyDoc doc = tidyCreate();
  if (!doc) goto cleanup_buffers;
  
  // 配置（步骤1）
  if (tidySetErrorBuffer(doc, &error_buffer) < 0) goto cleanup_doc;
  tidyOptSetBool(doc, TidyXhtmlOut, yes);
  tidyOptSetBool(doc, TidyForceOutput, yes);
  
  // 解析（步骤2）
  if (tidyParseBuffer(doc, &input_buffer) < 0) goto cleanup_doc;
  
  // 清理和修复（步骤3）
  if (tidyCleanAndRepair(doc) < 0) goto cleanup_doc;
  
  // 运行诊断（步骤4）
  if (tidyRunDiagnostics(doc) < 0) goto cleanup_doc;
  
  // 保存输出（步骤5）
  tidySaveBuffer(doc, &output_buffer);
  
cleanup_doc:
  tidyRelease(doc);
cleanup_buffers:
  tidyBufFree(&error_buffer);
  tidyBufFree(&output_buffer);
  tidyBufDetach(&input_buffer);
  return 0;
}
```

**参考实例**: `tidy-html5/tidy_fuzzer.c`

---

### 🔹 场景 9: 证书/密钥解析（简单但需检查返回值）

**适用于**: mbedtls, OpenSSL, BoringSSL

```c
#include <stddef.h>
#include <stdint.h>
#include "mbedtls/x509_crt.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  
#if defined(MBEDTLS_USE_PSA_CRYPTO)
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    goto cleanup;
  }
#endif
  
  // 解析证书
  int ret = mbedtls_x509_crt_parse(&crt, data, size);
  
  if (ret == 0) {
    // 获取证书信息
    char buf[4096];
    mbedtls_x509_crt_info(buf, sizeof(buf) - 1, " ", &crt);
  }
  
cleanup:
#if defined(MBEDTLS_USE_PSA_CRYPTO)
  mbedtls_psa_crypto_free();
#endif
  mbedtls_x509_crt_free(&crt);
  return 0;
}
```

**参考实例**: `mbedtls/fuzz_x509crt.c`

---

### 🔹 场景 10: 网络协议（复杂，多种模式）

**适用于**: curl, HTTP 解析器

这个场景非常复杂，建议查看完整实现。核心要点：

1. 使用 TLV（Type-Length-Value）格式解析输入
2. Mock 网络 I/O（socketpair, pipe）
3. 设置超时防止挂起

```cpp
// 简化版框架
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) return 0;
  
  // 解析 TLV 格式的命令和响应
  FuzzData fuzz;
  init_fuzz_data(&fuzz, data, size);
  
  // 创建 curl handle
  CURL *easy = curl_easy_init();
  if (!easy) return 0;
  
  // 配置选项（从输入提取）
  parse_curl_options(&fuzz, easy);
  
  // Hook socket 创建（使用 socketpair）
  curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION, fake_socket);
  
  // 设置超时
  curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 200L);
  
  // 执行请求（会触发 fake socket 返回数据）
  CURLcode ret = curl_easy_perform(easy);
  
  curl_easy_cleanup(easy);
  cleanup_fuzz_data(&fuzz);
  return 0;
}
```

**参考实例**: `curl/curl_fuzzer.cc` （非常复杂，约600行）

---

### 🔹 场景 11: 数据库/SQL（持久化上下文 + 信号处理）

**适用于**: SQLite, PostgreSQL

```c
#include <stddef.h>
#include <stdint.h>
#include "sqlite3.h"

// 限制选项
#define MAX_TIME_MS 10000
#define MAX_MEMORY 20000000
#define MAX_LENGTH 50000

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3) return 0;
  
  // 初始化
  if (sqlite3_initialize() != SQLITE_OK) return 0;
  
  // 打开内存数据库
  sqlite3 *db;
  if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 0;
  
  // 设置资源限制
  sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 25000);
  sqlite3_hard_heap_limit64(MAX_MEMORY);
  sqlite3_limit(db, SQLITE_LIMIT_LENGTH, MAX_LENGTH);
  
  // 设置进度回调（超时控制）
  // sqlite3_progress_handler(db, 10, progress_handler, &context);
  
  // 复制SQL到null结尾的字符串
  char *sql = sqlite3_mprintf("%.*s", (int)size, data);
  if (!sql) goto cleanup;
  
  // 执行SQL
  char *error_msg = NULL;
  sqlite3_exec(db, sql, NULL, NULL, &error_msg);
  
  sqlite3_free(error_msg);
  sqlite3_free(sql);
  
cleanup:
  sqlite3_close(db);
  return 0;
}
```

**关键要点**:
- ✅ 使用内存数据库 (`:memory:`)
- ✅ 设置各种资源限制
- ✅ 使用 progress_handler 实现超时
- ⚠️ PostgreSQL 需要 sigsetjmp 处理（更复杂）

**参考实例**: `sqlite3/ossfuzz.c`, `postgresql/json_parser_fuzzer.c`

---

## 常见问题解决方案

### Q1: API 需要 NULL 结尾的字符串怎么办？

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 方法1: 分配 size+1
  char *str = malloc(size + 1);
  if (!str) return 0;
  memcpy(str, data, size);
  str[size] = '\0';
  
  api_that_needs_string(str);
  
  free(str);
  return 0;
}

// 方法2: 如果 API 支持长度参数
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  api_with_length((const char *)data, size);
  return 0;
}
```

---

### Q2: 如何从输入提取多个参数（C 语言）？

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 确保有足够的数据
  if (size < 5) return 0;
  
  // 提取参数
  int param1 = data[0];                  // 1字节
  int param2 = data[1] | (data[2] << 8); // 2字节
  bool param3 = data[3] & 1;             // 1字节
  int param4 = data[4];                  // 1字节
  
  // 剩余数据
  const uint8_t *payload = data + 5;
  size_t payload_size = size - 5;
  
  api_function(param1, param2, param3, param4, payload, payload_size);
  return 0;
}
```

---

### Q3: 如何从输入提取多个参数（C++）？

```cpp
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  // 类型安全的提取
  int param1 = fdp.ConsumeIntegral<int>();
  uint16_t param2 = fdp.ConsumeIntegral<uint16_t>();
  bool param3 = fdp.ConsumeBool();
  float param4 = fdp.ConsumeFloatingPoint<float>();
  
  // 固定长度的字节
  std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(10);
  
  // 固定长度的字符串
  std::string str = fdp.ConsumeBytesAsString(20);
  
  // 剩余所有数据
  std::vector<uint8_t> remaining = fdp.ConsumeRemainingBytes<uint8_t>();
  
  api_function(param1, param2, param3, param4, ...);
  return 0;
}
```

**FuzzedDataProvider 常用方法**:
- `ConsumeIntegral<T>()` - 整数（自动处理大小端）
- `ConsumeBool()` - 布尔值
- `ConsumeFloatingPoint<T>()` - 浮点数
- `ConsumeBytes<T>(size)` - 固定长度字节
- `ConsumeBytesAsString(size)` - 固定长度字符串
- `ConsumeRandomLengthString(max)` - 随机长度字符串
- `ConsumeRemainingBytes<T>()` - 所有剩余数据
- `PickValueInArray()` - 从数组中选择
- `ConsumeEnum<T>()` - 枚举值

---

### Q4: 如何避免无限循环？

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  obj_t *obj = obj_create(data, size);
  
  // 错误：无限循环
  // while (has_more_data(obj)) {
  //   process_next(obj);
  // }
  
  // 正确：添加上限
  int max_iterations = 1000;
  while (has_more_data(obj) && max_iterations-- > 0) {
    process_next(obj);
  }
  
  obj_destroy(obj);
  return 0;
}
```

---

### Q5: 如何处理需要初始化的库？

**方法1: LLVMFuzzerInitialize（推荐）**
```c
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  // 全局初始化，只执行一次
  library_global_init();
  load_config_files();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 使用已初始化的库
  library_process(data, size);
  return 0;
}
```

**方法2: static 标志**
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static int initialized = 0;
  if (!initialized) {
    library_init();
    initialized = 1;
  }
  
  library_process(data, size);
  return 0;
}
```

---

### Q6: 如何限制内存使用？

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 方法1: 限制输入大小
  if (size > 100 * 1024) return 0;  // 最大100KB
  
  // 方法2: 限制分配大小
  size_t buffer_size = size * 2;
  if (buffer_size > 10 * 1024 * 1024) {  // 最大10MB
    buffer_size = 10 * 1024 * 1024;
  }
  
  uint8_t *buffer = malloc(buffer_size);
  if (!buffer) return 0;  // OOM 保护
  
  api_process(data, size, buffer, buffer_size);
  
  free(buffer);
  return 0;
}
```

对于支持的库：
```c
// SQLite
sqlite3_hard_heap_limit64(20000000);  // 20MB

// libxml2
xmlSetMaxMemory(100 * 1024 * 1024);  // 100MB
```

---

### Q7: 如何处理需要多个输入文件的 API？

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) return 0;
  
  // 第一个文件的大小（2字节）
  size_t file1_size = data[0] | (data[1] << 8);
  data += 2; size -= 2;
  
  if (file1_size > size) file1_size = size;
  
  // 写第一个文件
  char file1[256], file2[256];
  sprintf(file1, "/tmp/fuzz1_%d", getpid());
  sprintf(file2, "/tmp/fuzz2_%d", getpid());
  
  FILE *fp1 = fopen(file1, "wb");
  if (fp1) {
    fwrite(data, file1_size, 1, fp1);
    fclose(fp1);
  }
  
  // 写第二个文件
  const uint8_t *file2_data = data + file1_size;
  size_t file2_size = size - file1_size;
  
  FILE *fp2 = fopen(file2, "wb");
  if (fp2) {
    fwrite(file2_data, file2_size, 1, fp2);
    fclose(fp2);
  }
  
  // 调用 API
  api_process_two_files(file1, file2);
  
  // 清理
  unlink(file1);
  unlink(file2);
  return 0;
}
```

---

## 完整代码模板

### 模板 A: 最简单（C语言，纯函数）

```c
#include <stddef.h>
#include <stdint.h>
#include "your_api.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  your_api_function(data, size);
  return 0;
}
```

---

### 模板 B: 标准模板（C语言，带资源管理）

```c
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "your_api.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 1. 输入验证
  if (size < 10 || size > 100 * 1024) return 0;
  
  // 2. 创建对象
  api_obj_t *obj = api_create();
  if (!obj) return 0;
  
  // 3. 分配缓冲区
  uint8_t *buffer = malloc(size * 2);
  if (!buffer) goto cleanup_obj;
  
  // 4. 配置
  api_set_option(obj, OPT_SAFE_MODE, 1);
  
  // 5. 处理
  int ret = api_process(obj, data, size, buffer);
  if (ret != API_SUCCESS) goto cleanup_all;
  
  // 6. 更多操作...
  
cleanup_all:
  free(buffer);
cleanup_obj:
  api_destroy(obj);
  return 0;
}
```

---

### 模板 C: 标准模板（C++，带异常处理）

```cpp
#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <vector>
#include "your_api.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 1. 输入验证
  if (size < 1) return 0;
  
  // 2. 提取参数
  FuzzedDataProvider fdp(data, size);
  auto param1 = fdp.ConsumeIntegral<int>();
  auto param2 = fdp.ConsumeBool();
  auto input = fdp.ConsumeRemainingBytes<uint8_t>();
  
  try {
    // 3. 创建对象（RAII）
    YourObject obj(param1, param2);
    
    // 4. 处理
    obj.process(input.data(), input.size());
    
    // 5. 更多操作...
    auto result = obj.get_result();
    
  } catch (const std::exception& e) {
    // 预期的异常
  } catch (...) {
    // 捕获所有异常
  }
  
  return 0;  // RAII 自动清理
}
```

---

### 模板 D: 生产级模板（包含所有最佳实践）

```c
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "your_api.h"

// 全局初始化（如果需要）
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  api_global_init();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // === 1. 输入验证 ===
  if (size < 10) return 0;            // 最小大小
  if (size > 100 * 1024) return 0;    // 最大大小（100KB）
  
  // === 2. 提取参数（如果需要）===
  int flags = data[0];
  data++; size--;
  
  // === 3. 创建主对象 ===
  api_obj_t *obj = api_create();
  if (!obj) return 0;
  
  // === 4. 分配资源 ===
  size_t buffer_size = size * 2;
  uint8_t *buffer = malloc(buffer_size);
  if (!buffer) goto cleanup_obj;
  
  uint8_t *output = malloc(buffer_size);
  if (!output) goto cleanup_buffer;
  
  // === 5. 配置对象 ===
  api_set_option(obj, OPT_TIMEOUT, 1000);
  api_set_option(obj, OPT_MAX_MEMORY, 10 * 1024 * 1024);
  if (flags & 0x01) api_set_option(obj, OPT_STRICT_MODE, 1);
  
  // === 6. 主要处理 ===
  int ret = api_process(obj, data, size, buffer, buffer_size);
  if (ret != API_SUCCESS) goto cleanup_all;
  
  // === 7. 额外操作（如果需要）===
  size_t output_size;
  ret = api_get_output(obj, output, buffer_size, &output_size);
  if (ret == API_SUCCESS && output_size > 0) {
    // 验证输出
    api_validate_output(output, output_size);
  }
  
  // === 8. 迭代操作（如果需要，带限制）===
  int max_iter = 100;
  while (api_has_more(obj) && max_iter-- > 0) {
    api_process_next(obj);
  }
  
  // === 9. 清理（按照相反的顺序）===
cleanup_all:
  free(output);
cleanup_buffer:
  free(buffer);
cleanup_obj:
  api_destroy(obj);
  return 0;
}
```

---

## 调试和优化技巧

### 本地测试

```bash
# 1. 编译 fuzzer
clang -g -O1 -fsanitize=fuzzer,address your_fuzzer.c -o fuzzer

# 2. 运行（会自动生成测试用例）
./fuzzer

# 3. 运行指定次数
./fuzzer -runs=10000

# 4. 限制时间
./fuzzer -max_total_time=60

# 5. 重现崩溃
./fuzzer crash-filename

# 6. 最小化崩溃用例
./fuzzer -minimize_crash=1 crash-filename
```

### 性能优化

```c
// ✅ 好：使用静态缓冲区（如果大小固定）
static uint8_t buffer[256 * 1024];

// ❌ 坏：每次都 malloc/free
uint8_t *buffer = malloc(256 * 1024);
// ...
free(buffer);
```

### 检查覆盖率

```bash
# 编译带覆盖率的 fuzzer
clang -g -O1 -fsanitize=fuzzer,address -fprofile-instr-generate \
      -fcoverage-mapping your_fuzzer.c -o fuzzer

# 运行
./fuzzer corpus/ -runs=10000

# 生成覆盖率报告
llvm-profdata merge -o fuzzer.profdata default.profraw
llvm-cov show ./fuzzer -instr-profile=fuzzer.profdata
```

### 添加字典（提高效率）

创建 `fuzzer.dict`:
```
# JSON 关键字
keyword_true="true"
keyword_false="false"
keyword_null="null"

# 常见分隔符
delimiter_colon=":"
delimiter_comma=","
delimiter_brace_open="{"
delimiter_brace_close="}"

# 魔术数字
magic_png="\x89PNG"
magic_jpeg="\xFF\xD8\xFF"
```

使用字典:
```bash
./fuzzer -dict=fuzzer.dict corpus/
```

---

**文档版本**: 1.0  
**数据来源**: 基于 4699 个真实 fuzzer 分析  
**最后更新**: 2025-10-27

🎯 **提示**: 将本手册加入书签，编写fuzzer时随时查阅！

