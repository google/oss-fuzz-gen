# Fuzzer 速查表 (Cheat Sheet)

> **📌 文档类型**: 📚 **参考文档（快速参考）**  
> **最后更新**: 2025-11-01  
> **内容来源**: OSS-Fuzz 最佳实践总结
>
> 💡 **用途说明**: 
> - 一页纸快速参考
> - 3 个标准模板（5行/20行/40行）
> - 常见错误和解决方案
> - **与 LogicFuzz 实现独立**，可作为通用速查表
>
> **相关文档**:
> - [FUZZER_COOKBOOK.md](FUZZER_COOKBOOK.md) - 完整代码模板
> - [FUZZER_BEHAVIOR_TAXONOMY.md](FUZZER_BEHAVIOR_TAXONOMY.md) - 详细分类
> - [README_FUZZING.md](README_FUZZING.md) - 总目录

---

## 🎯 根据你的 API，选择模式

```
┌─────────────────────────────────────────────────────────────────┐
│                    API 类型 → 推荐模式                           │
├─────────────────────────────────────────────────────────────────┤
│ 哈希/校验和           → 无状态解析器（最简）                     │
│ JSON/XML/YAML        → 无状态解析器 / 流式处理器                 │
│ 图像(PNG/JPEG)       → 临时文件 + 异常处理                       │
│ ZIP/TAR/RAR          → 迭代器 + 对象生命周期                     │
│ zlib/bzip2           → 往返转换器（压缩+解压）                   │
│ 加密/解密             → 往返转换器 + 伪随机控制                  │
│ HTTP 解析            → 协议解析器 + 条件分支                     │
│ 正则表达式           → 结构化输入提取                            │
│ 数据库协议           → 协议状态机 + Hook（高级）                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📝 三个标准模板

### 1️⃣ 最简模板（5 行代码）
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  your_api(data, size);
  return 0;
}
```

### 2️⃣ C 标准模板（带资源管理）
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10 || size > 100*1024) return 0;
  
  obj_t *obj = obj_create();
  if (!obj) return 0;
  
  int ret = obj_process(obj, data, size);
  if (ret != OK) goto cleanup;
  
  // 更多操作...
  
cleanup:
  obj_destroy(obj);
  return 0;
}
```

### 3️⃣ C++ 标准模板（带异常处理）
```cpp
#include <fuzzer/FuzzedDataProvider.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  try {
    auto param1 = fdp.ConsumeIntegral<int>();
    auto param2 = fdp.ConsumeBool();
    auto input = fdp.ConsumeRemainingBytes();
    
    Object obj(param1, param2);
    obj.process(input.data(), input.size());
  } catch (...) {}
  
  return 0;
}
```

---

## ⚠️ 四大致命错误

```
❌ 修改输入       data[0] = 0;  // libFuzzer 会崩溃
✅ 复制后修改     memcpy(copy, data, size); copy[0] = 0;

❌ 资源泄漏       obj = create(); if (err) return 0;
✅ goto 清理      if (err) goto cleanup; ... cleanup: destroy(obj);

❌ 栈溢出         uint8_t buf[10*1024*1024];  // 栈上
✅ 堆分配         uint8_t *buf = malloc(10*1024*1024);

❌ 无限循环       while (has_data()) process();
✅ 加上限         int n=1000; while (has_data() && n-->0) process();
```

---

## 🔧 常见问题速解

### Q1: API 需要文件路径？
```c
char fname[256];
sprintf(fname, "/tmp/fuzz_%d.dat", getpid());
FILE *f = fopen(fname, "wb");
fwrite(data, size, 1, f);
fclose(f);

api_process_file(fname);
unlink(fname);  // 清理
```

### Q2: API 使用随机数？
```cpp
setup_fake_random(data, size);  // 替换 RNG
api_that_uses_random();         // 现在确定性
```

### Q3: 多个参数？
```cpp
FuzzedDataProvider fdp(data, size);
int p1 = fdp.ConsumeIntegral<int>();
bool p2 = fdp.ConsumeBool();
std::string p3 = fdp.ConsumeBytesAsString(10);
auto remaining = fdp.ConsumeRemainingBytes();
```

### Q4: 昂贵初始化？
```cpp
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  load_config();  // 只执行一次
  return 0;
}
```

### Q5: 测试多 API 组合？
```c
while (size > 0) {
  int op = data[0] % NUM_OPS;
  data++; size--;
  
  switch(op) {
    case 0: obj_read(...); break;
    case 1: obj_write(...); break;
    case 2: obj_seek(...); break;
  }
}
```

---

## 📊 性能优化 4 招

```
1. 限制输入     if (size > 100*1024) return 0;
2. 静态缓冲     static uint8_t buf[256*1024];  // 重用
3. 限制迭代     int n=1000; while(...&& n-->0) {...}
4. 一次初始化   LLVMFuzzerInitialize() 中设置
```

---

## ✅ 质量检查 6 步

```
实现时必查：
□ 输入大小检查（最小/最大）
□ 所有 API 返回值/异常检查
□ 所有资源配对清理
□ 不修改输入数据
□ 无无限循环
□ 无大栈分配
```

---

## 🎓 学习路径（3 级）

```
🟢 初级：无状态解析器
   示例：zlib/checksum_fuzzer.c
   时间：1 小时

🟡 中级：对象生命周期 + 临时文件
   示例：libarchive/libarchive_fuzzer.cc
   时间：1 天

🔴 高级：协议状态机 + Hook
   示例：postgresql/protocol_fuzzer.c
   时间：1 周
```

---

## 🔍 决策树（30 秒版）

```
单函数？           → 无状态解析器
  └ 示例: checksum_fuzzer.c

需要文件？         → 临时文件
  └ 示例: imread_fuzzer.cc

编码+解码？        → 往返转换器
  └ 示例: compress_fuzzer.c

遍历容器？         → 迭代器
  └ 示例: libarchive_fuzzer.cc

多步骤序列？       → 状态机
  └ 示例: tidy_fuzzer.c

复杂协议？         → 协议状态机（高级）
  └ 示例: postgresql/protocol_fuzzer.c
```

---

## 📚 完整文档

- **中文快速入门**: `API_FUZZING_PATTERNS_中文摘要.md`
- **详细分类**: `FUZZER_API_CLASSIFICATION.md`
- **实用指南**: `FUZZER_PATTERN_QUICK_GUIDE.md`
- **总索引**: `README_FUZZING_PATTERNS.md`

---

## 🚀 60 秒开始 Fuzzing

```bash
# 1. 创建 fuzzer.c
cat > fuzzer.c << 'EOF'
#include <stddef.h>
#include <stdint.h>
#include "your_api.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  your_api(data, size);
  return 0;
}
EOF

# 2. 编译
clang -g -O1 -fsanitize=fuzzer,address fuzzer.c -o fuzzer

# 3. 运行
./fuzzer

# 4. 重现崩溃
./fuzzer crash-file
```

---

## 🎯 常用命令

```bash
# 限制运行次数
./fuzzer -runs=1000

# 限制时间
./fuzzer -max_total_time=60

# 每输入超时
./fuzzer -timeout=10

# 语料库最小化
./fuzzer -merge=1 corpus_min corpus

# 使用字典
./fuzzer -dict=fuzzer.dict

# 详细输出
./fuzzer -verbosity=2

# 并行 fuzzing
./fuzzer -jobs=8 -workers=8
```

---

## 📈 成功指标

```
✅ 性能:    exec/s > 100 (简单) 或 > 10 (复杂)
✅ 稳定性:  无崩溃，无泄漏
✅ 覆盖率:  覆盖主要代码路径
✅ 可维护:  代码清晰易懂
```

---

**速查表版本**: 1.0  
**完整文档**: 见上方链接  
**最后更新**: 2025-10-27

---

```
                      Happy Fuzzing! 🐛
         
         找到 bug ← 你的 fuzzer ← 这份速查表 ← 开始！
```

