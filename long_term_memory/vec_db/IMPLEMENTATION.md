# 向量数据库实现说明

## 当前实现架构

当前的向量数据库实现使用**Chroma**作为专业的向量数据库，替代了之前的 CSV 文件方案。

### 1. 存储方式

**数据库**: Chroma (本地持久化数据库)

**存储位置**: `./chroma_db/` 目录（可配置）

**Collection**: `driver_code` (可配置)

**存储结构**:
- **IDs**: 基于文件路径生成的唯一标识符
- **Embeddings**: 3072 维向量（OpenAI text-embedding-3-large）
- **Documents**: 用于搜索的文本（包含元数据和代码片段）
- **Metadatas**: 
  - `file_path`: 驱动文件路径
  - `project`: 项目名称
  - `api_name`: API 函数名
  - `api_type`: API 类型/archetype
  - `code_content`: 代码内容（截断到 50KB，完整代码从文件读取）
  - `code_length`: 完整代码长度

### 2. Embedding 生成

**模型**: OpenAI `text-embedding-3-large`

**生成流程**:
1. 读取 driver 代码文件
2. 提取元数据（project, api_name, api_type）
3. 构建 embedding 文本：
   ```
   Project: {project}
   API: {api_name}
   API Type: {api_type}
   
   Code:
   {code_content[:8000]}  # 限制 8000 字符
   ```
4. 调用 OpenAI API 生成 embedding（3072 维向量）

**代码位置**: `driver_indexer.py::_get_embedding()`

### 3. 相似度计算

**方法**: 余弦相似度（Cosine Similarity）

**计算公式**:
```python
similarity = 1 - cosine(query_embedding, stored_embedding)
```

**实现**:
- 使用 `scipy.spatial.distance.cosine` 计算余弦距离
- 相似度 = 1 - 余弦距离（值越大越相似，范围 0-1）

**代码位置**: `driver_indexer.py::search_similar()` (line 327-328)

### 4. 检索方式

**当前实现**: **Chroma 向量相似度搜索（近似最近邻）**

**流程**:
1. 生成查询文本的 embedding
2. 使用 Chroma 的 `query()` 方法进行向量相似度搜索
3. 支持元数据过滤（project, api_type）
4. 自动计算余弦相似度并排序
5. 根据 threshold 过滤结果
6. 返回 top-n 结果

**性能特点**:
- ✅ 高性能：使用近似最近邻算法（HNSW）
- ✅ 支持大规模数据（百万级向量）
- ✅ 元数据过滤优化
- ✅ 持久化存储，无需每次加载
- ✅ 支持增量索引

**代码位置**: `driver_indexer.py::search_similar()` (line 308-393)

### 5. API 类型推断

**方法**: 基于正则表达式的模式匹配

**支持的 API 类型**:
- `simple_function_call`: 简单函数调用
- `object_lifecycle`: 对象生命周期（init/create → use → destroy/free）
- `streaming_api`: 流式处理（循环调用）
- `callback_api`: 回调函数 API
- `file_path_api`: 文件路径 API
- `multi_parameter_api`: 多参数 API
- `exception_handling_api`: 异常处理 API

**推断逻辑**:
1. 对每种 API 类型定义多个正则模式
2. 统计代码中匹配每个类型的模式数量
3. 返回匹配数最多的类型

**代码位置**: `driver_indexer.py::_infer_api_type()` (line 127-148)

### 6. 检索接口

**高级接口**: `DriverCodeRetriever` 类

**主要方法**:
- `search_by_description()`: 自然语言描述搜索
- `search_by_code_snippet()`: 代码片段搜索
- `search_by_api_name()`: API 函数名搜索
- `get_examples_by_type()`: 按 API 类型获取示例
- `get_examples_by_project()`: 按项目获取示例

**代码位置**: `driver_retriever.py`

## 使用示例

### 索引所有 driver 代码

```python
from long_term_memory.vec_db.driver_indexer import DriverCodeIndexer

indexer = DriverCodeIndexer(
    drivers_dir="extracted_fuzz_drivers",
    persist_directory="./chroma_db",
    collection_name="driver_code"
)
indexer.index_all_drivers()
```

### 搜索相似代码

```python
from long_term_memory.vec_db.driver_retriever import DriverCodeRetriever

retriever = DriverCodeRetriever(
    persist_directory="./chroma_db",
    collection_name="driver_code"
)

# 按描述搜索
results = retriever.search_by_description(
    "streaming API with loop and iteration limit",
    api_type="streaming_api",
    n=5,
    threshold=0.7
)

# 按代码片段搜索
results = retriever.search_by_code_snippet(
    "while (stream_next()) { process(); }",
    n=3
)
```

## 优缺点分析

### ✅ 优点

1. **高性能**: 使用 HNSW 算法，支持快速近似最近邻搜索
2. **可扩展**: 支持百万级向量，性能稳定
3. **持久化**: 数据自动持久化到磁盘，无需手动管理
4. **元数据过滤**: 支持高效的元数据过滤（project, api_type）
5. **增量索引**: 支持增量添加，无需重建整个索引
6. **本地运行**: 无需外部服务，本地即可运行

### ⚠️ 局限性

1. **依赖**: 需要安装 ChromaDB 库
2. **存储空间**: 向量数据需要一定存储空间（每个向量约 12KB）
3. **初始化**: 首次索引需要生成所有 embeddings（可能较慢）

## 可能的改进方向

### 1. 混合检索

**结合**:
- 向量相似度搜索（当前已实现）
- 关键词搜索（BM25）
- 元数据过滤（project, api_type，当前已支持）

### 2. 性能优化

**改进点**:
- 批量生成 embeddings（减少 API 调用）
- 缓存常用查询结果
- 使用更快的 embedding 模型（如 text-embedding-3-small）

### 3. 功能扩展

**新增功能**:
- 支持多模态搜索（代码 + 注释）
- 支持代码片段级别的检索
- 支持相似代码的聚类分析

## 文件结构

```
long_term_memory/vec_db/
├── driver_indexer.py      # 索引器：生成 embeddings 并存储到 Chroma
├── driver_retriever.py    # 检索器：提供高级检索接口
└── IMPLEMENTATION.md      # 本文档
```

## 依赖项

```python
# 核心依赖
chromadb        # 向量数据库（>= 0.4.0）
openai          # Embedding 生成
tqdm            # 进度条显示
```

## 总结

当前实现使用**Chroma 向量数据库**，提供了高性能、可扩展的向量搜索能力。适合从小规模到大规模（百万级）的数据检索需求。相比之前的 CSV 方案，性能提升显著，且支持更丰富的查询功能。

