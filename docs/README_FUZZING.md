# Fuzzer 编写指南

**基于 4,699 个真实 OSS-Fuzz 项目的系统分析**

---

## 📚 文档列表

### 1. FUZZER_COOKBOOK.md（推荐先看）
**内容**: 11种典型场景的完整代码模板
- ✅ 可以直接复制粘贴使用
- ✅ 包含真实项目参考
- ✅ 解决常见问题

**适合**: 
- 需要快速写一个 fuzzer
- 遇到具体技术问题
- 想找参考实现

**使用方法**:
1. 找到你的 API 类型（JSON解析、图像处理、压缩等）
2. 复制对应的完整代码模板
3. 修改成你的 API

---

### 2. FUZZER_BEHAVIOR_TAXONOMY.md（深入学习）
**内容**: 系统化的5维度分类框架
- 📐 5大行为维度详解
- 🎨 8个典型组合模式
- 🔍 决策流程图
- ⚠️ 常见陷阱

**适合**:
- 想系统理解 fuzzer 设计原理
- 面对复杂 API 不知如何下手
- 想写出高质量的 fuzzer

**5大维度**:
1. 输入数据处理方式
2. 状态管理模式
3. 资源生命周期管理
4. API调用模式
5. 错误处理策略

---

### 3. FUZZING_CHEATSHEET.md（速查）
**内容**: 一页纸快速参考
- ⚡ 3个标准模板（5行/20行/40行）
- ⚠️ 7大致命错误
- 💡 常见问题速解
- 📈 命令行参考

**适合**:
- 有经验的开发者
- 快速查询某个问题
- 记不清某个语法

---

## 🚀 快速开始

### 60秒写出第一个 fuzzer

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

编译运行：
```bash
clang -g -O1 -fsanitize=fuzzer,address fuzzer.c -o fuzzer -lyour_lib
./fuzzer
```

详见 `FUZZING_CHEATSHEET.md`

---

## 🎯 按场景选择文档

| 你的需求 | 推荐文档 | 章节 | 时间 |
|---------|---------|------|------|
| 快速写一个简单的 fuzzer | FUZZING_CHEATSHEET.md | 最简模板 | 5分钟 |
| 为 JSON/XML 解析器写 fuzzer | FUZZER_COOKBOOK.md | §1 简单解析器 | 15分钟 |
| API 需要文件路径怎么办 | FUZZER_COOKBOOK.md | §2 文件路径API | 15分钟 |
| 如何提取多个参数 | FUZZER_COOKBOOK.md | 常见问题 §1 | 10分钟 |
| 不知道选什么模式 | FUZZER_BEHAVIOR_TAXONOMY.md | 决策流程 | 20分钟 |
| 系统学习 fuzzer 设计 | FUZZER_BEHAVIOR_TAXONOMY.md | 从头读 | 2小时 |

---

## 📊 按 API 类型快速查找

| API 类型 | 参考 Fuzzer | 文档位置 |
|---------|------------|---------|
| JSON/XML/YAML | `libyaml/libyaml_parser_fuzzer.c` | Cookbook §1 |
| 图像解码 | `opencv/imdecode_fuzzer.cc` | Cookbook §3 |
| 图像加载（文件） | `opencv/imread_fuzzer.cc` | Cookbook §2 |
| ZIP/TAR | `libarchive/libarchive_fuzzer.cc` | Cookbook §7 |
| 压缩/解压 | `zlib/compress_fuzzer.c` | Cookbook §4 |
| 加密/解密 | `libsodium/secretbox_easy_fuzzer.cc` | Cookbook §5 |
| 正则表达式 | `re2/re2_fuzzer.cc` | Cookbook §6 |
| HTML 清理 | `tidy-html5/tidy_fuzzer.c` | Cookbook §8 |
| 证书解析 | `mbedtls/fuzz_x509crt.c` | Cookbook §9 |
| HTTP 协议 | `curl/curl_fuzzer.cc` | Cookbook §10 |
| SQL | `sqlite3/ossfuzz.c` | Cookbook §11 |

完整列表见 `FUZZER_COOKBOOK.md` 开头

---

## ⚠️ 必须避免的7大错误

1. ❌ 修改输入数据 → ✅ 复制到自己的缓冲区
2. ❌ 资源泄漏 → ✅ 用 `goto cleanup`
3. ❌ 无限循环 → ✅ 加上限 `while(...&& n-->0)`
4. ❌ 栈溢出 → ✅ 大数组用 malloc
5. ❌ 不检查 malloc → ✅ `if (!buf) return 0`
6. ❌ 未捕获异常 → ✅ C++ 用 try-catch
7. ❌ 随机数 → ✅ 从输入派生或用 fake_random

详见 `FUZZER_BEHAVIOR_TAXONOMY.md` 附录

---

## 🎓 学习路径

### 新手（第一次写 fuzzer）
1. 阅读 `FUZZING_CHEATSHEET.md` 的"60秒快速开始" (5分钟)
2. 复制最简模板，改成你的 API (10分钟)
3. 编译运行 (5分钟)
4. 如果出错，查 `FUZZER_COOKBOOK.md` 常见问题 (10分钟)

**总计**: 30 分钟

---

### 初级（1-5 个 fuzzer 经验）
1. 浏览 `FUZZER_COOKBOOK.md` 所有场景 (1小时)
2. 为不同类型的 API 写 fuzzer (实践)
3. 对比参考实现，改进代码

**总计**: 1-2 周

---

### 中级（5+ 个 fuzzer 经验）
1. 系统学习 `FUZZER_BEHAVIOR_TAXONOMY.md` (2小时)
2. 研究复杂的参考实现
3. 学习覆盖率优化

**总计**: 持续学习

---

## 💡 实用技巧

### 命令行
```bash
# 运行指定次数
./fuzzer -runs=10000

# 限制时间
./fuzzer -max_total_time=60

# 重现崩溃
./fuzzer crash-file

# 最小化崩溃用例
./fuzzer -minimize_crash=1 crash-file
```

### 使用字典
```bash
echo 'keyword_true="true"' > fuzzer.dict
echo 'keyword_false="false"' >> fuzzer.dict
./fuzzer -dict=fuzzer.dict
```

更多技巧见 `FUZZING_CHEATSHEET.md`

---

## 🔗 外部资源

- **libFuzzer 官方文档**: https://llvm.org/docs/LibFuzzer.html
- **OSS-Fuzz**: https://google.github.io/oss-fuzz/
- **FuzzedDataProvider**: https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h

---

## 📈 成功标准

好的 fuzzer 应该达到：
- **性能**: > 100 exec/s (简单) 或 > 10 exec/s (复杂)
- **稳定性**: 0 崩溃/泄漏（ASan 检查）
- **覆盖率**: > 70% 代码覆盖
- **可维护性**: < 200 行代码

---

## 📊 数据来源

本指南基于对 **OSS-Fuzz** 项目的系统分析：
- **4,699** 个 fuzz driver 源文件
- **350+** 个开源项目
- **24种** 基础模式 + **8种** 典型组合

---

**下一步**: 
- 快速开始 → 打开 `FUZZING_CHEATSHEET.md`
- 找模板 → 打开 `FUZZER_COOKBOOK.md`
- 深入学习 → 打开 `FUZZER_BEHAVIOR_TAXONOMY.md`

**祝你 Fuzzing 愉快！** 🐛

