# Driver生成知识库 - 设计方案

## 📋 概述

### 背景与动机

在fuzzing driver生成过程中，我们面临以下挑战：

1. **重复错误**：相似的编译错误在不同项目中反复出现
2. **缺乏参考**：LLM缺少具体的成功案例作为生成参考
3. **知识孤立**：每次运行都是"从零开始"，无法积累经验
4. **修复低效**：已知问题需要重新推理，浪费token和时间

**核心目标**：建立一个**持久化知识库**，让系统能够：
- 📚 从历史运行中学习成功模式
- 🔍 快速检索相似场景的参考代码
- 🛠️ 自动应用已知错误的修复方案
- 📊 数据驱动的质量改进

---

## 🏗️ 整体架构

### 三层知识体系

```
┌─────────────────────────────────────────────────────────────┐
│                    Knowledge Ecosystem                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Layer 1: Static Knowledge (long_term_memory/)              │
│  ├─ Archetypes (6种行为模式)                                │
│  ├─ Skeletons (代码模板)                                    │
│  └─ Pitfalls (通用陷阱)                                      │
│  特点: 人工整理、通用、不变                                  │
│                                                               │
│  Layer 2: Session Memory (state.session_memory)             │
│  ├─ API Constraints (API约束)                               │
│  ├─ Known Fixes (已知修复)                                  │
│  └─ Decisions (决策记录)                                     │
│  特点: 单次运行、临时、共享状态                              │
│                                                               │
│  Layer 3: Persistent Knowledge (knowledge_db/) 🆕           │
│  ├─ Historical Drivers (历史driver)                         │
│  ├─ Error Patterns (错误模式)                               │
│  ├─ Fix Transformations (修复转换)                          │
│  └─ API Usage Examples (API用法)                            │
│  特点: 自动积累、跨运行、持久化学习                          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### 技术架构

```
┌──────────────────────────────────────────────────────────┐
│                   Application Layer                       │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐        │
│  │ Prototyper │  │  Enhancer  │  │ Supervisor │        │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘        │
└────────┼────────────────┼────────────────┼──────────────┘
         │                │                │
         └────────────────┴────────────────┘
                          │
         ┌────────────────▼────────────────┐
         │   KnowledgeDatabase (统一接口)  │
         └────────────────┬────────────────┘
                          │
         ┌────────────────┴────────────────┐
         │                                  │
         ▼                                  ▼
┌─────────────────┐              ┌──────────────────┐
│  SQLite DB      │              │  Chroma Vector   │
│  (结构化数据)   │              │  (语义检索)      │
├─────────────────┤              ├──────────────────┤
│ • Projects      │              │ • driver_codes   │
│ • Functions     │              │ • error_contexts │
│ • Attempts      │              │ • api_snippets   │
│ • Errors        │              │                  │
│ • Fixes         │              │                  │
│ • Statistics    │              │                  │
└─────────────────┘              └──────────────────┘
```

---

## 📊 数据库设计

### SQLite Schema

#### 1. 核心实体表

```sql
-- ============================================================================
-- 项目管理
-- ============================================================================

CREATE TABLE projects (
    project_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT UNIQUE NOT NULL,
    language TEXT NOT NULL,  -- 'c', 'c++'
    description TEXT,
    oss_fuzz_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_projects_name ON projects(project_name);

-- ============================================================================
-- 目标函数
-- ============================================================================

CREATE TABLE functions (
    function_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    function_name TEXT NOT NULL,
    function_signature TEXT NOT NULL,
    header_file TEXT,
    source_file TEXT,
    
    -- 分类信息
    archetype TEXT,  -- stateless_parser, object_lifecycle, etc.
    complexity_score REAL,  -- 0-1, 基于参数数量、依赖等
    
    -- 统计信息
    total_attempts INTEGER DEFAULT 0,
    successful_attempts INTEGER DEFAULT 0,
    success_rate REAL DEFAULT 0.0,
    
    -- 时间戳
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_attempted TIMESTAMP,
    
    FOREIGN KEY (project_id) REFERENCES projects(project_id),
    UNIQUE(project_id, function_name)
);

CREATE INDEX idx_functions_name ON functions(function_name);
CREATE INDEX idx_functions_archetype ON functions(archetype);
CREATE INDEX idx_functions_project ON functions(project_id);

-- ============================================================================
-- Driver生成尝试记录
-- ============================================================================

CREATE TABLE driver_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id INTEGER NOT NULL,
    
    -- 运行上下文
    trial_number INTEGER,
    iteration INTEGER,
    agent_name TEXT,  -- 'prototyper', 'enhancer'
    
    -- 代码内容
    driver_code TEXT NOT NULL,
    driver_code_hash TEXT NOT NULL,  -- SHA256, 用于去重
    
    -- 结果状态
    status TEXT NOT NULL,  -- 'success', 'compile_error', 'runtime_error', 
                          -- 'timeout', 'crash', 'pending'
    
    -- 错误信息（如果失败）
    error_type TEXT,  -- 'missing_header', 'undefined_symbol', 'type_mismatch', etc.
    error_message TEXT,
    build_log TEXT,
    compiler_output TEXT,
    
    -- 性能指标（如果成功）
    coverage_percentage REAL,
    execution_time_ms INTEGER,
    
    -- 使用的知识
    used_references TEXT,  -- JSON: [attempt_id1, attempt_id2, ...]
    used_archetype TEXT,
    used_skeleton BOOLEAN DEFAULT 0,
    
    -- 时间戳
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (function_id) REFERENCES functions(function_id)
);

CREATE INDEX idx_attempts_function ON driver_attempts(function_id);
CREATE INDEX idx_attempts_status ON driver_attempts(status);
CREATE INDEX idx_attempts_hash ON driver_attempts(driver_code_hash);
CREATE INDEX idx_attempts_timestamp ON driver_attempts(generated_at);

-- ============================================================================
-- 编译错误模式
-- ============================================================================

CREATE TABLE error_patterns (
    error_id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- 错误分类
    error_type TEXT NOT NULL,  -- 'missing_header', 'undefined_symbol', etc.
    error_category TEXT,  -- 'compilation', 'linking', 'runtime'
    
    -- 模式匹配
    error_regex TEXT NOT NULL,  -- 用于匹配编译器输出
    error_keywords TEXT,  -- JSON array: ["undefined reference", "missing"]
    
    -- 描述
    description TEXT NOT NULL,
    severity TEXT,  -- 'critical', 'major', 'minor'
    
    -- 修复策略
    fix_strategy TEXT NOT NULL,  -- 描述修复方法
    fix_template TEXT,  -- 代码模板
    
    -- 统计信息
    occurrences INTEGER DEFAULT 1,
    fix_success_count INTEGER DEFAULT 0,
    fix_success_rate REAL DEFAULT 0.0,
    
    -- 时间戳
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(error_type, error_regex)
);

CREATE INDEX idx_errors_type ON error_patterns(error_type);
CREATE INDEX idx_errors_category ON error_patterns(error_category);

-- ============================================================================
-- 修复转换记录
-- ============================================================================

CREATE TABLE fix_transformations (
    fix_id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- 关联
    error_pattern_id INTEGER,
    failed_attempt_id INTEGER,  -- 失败的尝试
    success_attempt_id INTEGER,  -- 成功的尝试
    
    -- 转换内容
    before_code TEXT NOT NULL,  -- 错误的代码片段
    after_code TEXT NOT NULL,   -- 修复后的代码片段
    diff_patch TEXT,  -- unified diff format
    
    -- 上下文
    context_description TEXT,
    function_name TEXT,
    archetype TEXT,
    
    -- 效果评估
    effectiveness_score REAL DEFAULT 1.0,  -- 0-1
    reuse_count INTEGER DEFAULT 0,  -- 被重用次数
    
    -- 来源
    source TEXT,  -- 'manual', 'automated', 'llm_generated'
    confidence REAL DEFAULT 1.0,
    
    -- 时间戳
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    
    FOREIGN KEY (error_pattern_id) REFERENCES error_patterns(error_id),
    FOREIGN KEY (failed_attempt_id) REFERENCES driver_attempts(attempt_id),
    FOREIGN KEY (success_attempt_id) REFERENCES driver_attempts(attempt_id)
);

CREATE INDEX idx_fixes_error ON fix_transformations(error_pattern_id);
CREATE INDEX idx_fixes_effectiveness ON fix_transformations(effectiveness_score);

-- ============================================================================
-- API使用模式
-- ============================================================================

CREATE TABLE api_usage_patterns (
    pattern_id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- 关联
    function_id INTEGER,
    
    -- 用法分类
    usage_context TEXT NOT NULL,  -- 'initialization', 'pre_call', 'main_call', 
                                  -- 'post_call', 'cleanup', 'parameter_construction'
    
    -- 代码片段
    code_snippet TEXT NOT NULL,
    code_explanation TEXT,
    
    -- 分类
    archetype TEXT,
    complexity TEXT,  -- 'simple', 'moderate', 'complex'
    
    -- 质量指标
    confidence_score REAL DEFAULT 1.0,
    usage_count INTEGER DEFAULT 0,  -- 被使用次数
    success_rate REAL,  -- 使用此模式的成功率
    
    -- 来源
    source TEXT NOT NULL,  -- 'oss_fuzz', 'manual', 'extracted', 'generated'
    source_url TEXT,
    
    -- 时间戳
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    
    FOREIGN KEY (function_id) REFERENCES functions(function_id)
);

CREATE INDEX idx_api_patterns_function ON api_usage_patterns(function_id);
CREATE INDEX idx_api_patterns_context ON api_usage_patterns(usage_context);
CREATE INDEX idx_api_patterns_archetype ON api_usage_patterns(archetype);

-- ============================================================================
-- 头文件信息
-- ============================================================================

CREATE TABLE header_mappings (
    mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- 函数到头文件的映射
    function_id INTEGER NOT NULL,
    
    -- 头文件路径
    header_path TEXT NOT NULL,  -- 正确的路径
    header_type TEXT,  -- 'project', 'system', 'third_party'
    
    -- 别名/错误路径（LLM可能生成的）
    common_mistakes TEXT,  -- JSON array: ["wrong/path.h", "another/wrong.h"]
    
    -- 依赖关系
    depends_on TEXT,  -- JSON array: ["dep1.h", "dep2.h"]
    include_order INTEGER,  -- 推荐的include顺序
    
    -- 统计
    correct_usage_count INTEGER DEFAULT 0,
    mistake_count INTEGER DEFAULT 0,
    
    FOREIGN KEY (function_id) REFERENCES functions(function_id)
);

CREATE INDEX idx_headers_function ON header_mappings(function_id);
```

#### 2. 统计视图

```sql
-- ============================================================================
-- 实用视图
-- ============================================================================

-- 函数成功率统计
CREATE VIEW v_function_success_stats AS
SELECT 
    f.function_id,
    f.function_name,
    f.archetype,
    p.project_name,
    COUNT(d.attempt_id) as total_attempts,
    SUM(CASE WHEN d.status = 'success' THEN 1 ELSE 0 END) as successes,
    ROUND(100.0 * SUM(CASE WHEN d.status = 'success' THEN 1 ELSE 0 END) / 
          NULLIF(COUNT(d.attempt_id), 0), 2) as success_rate,
    MAX(d.generated_at) as last_attempt
FROM functions f
JOIN projects p ON f.project_id = p.project_id
LEFT JOIN driver_attempts d ON f.function_id = d.function_id
GROUP BY f.function_id;

-- 错误类型统计
CREATE VIEW v_error_frequency AS
SELECT 
    error_type,
    error_category,
    COUNT(*) as occurrence_count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM driver_attempts 
                               WHERE status != 'success'), 2) as percentage
FROM driver_attempts
WHERE status != 'success' AND error_type IS NOT NULL
GROUP BY error_type, error_category
ORDER BY occurrence_count DESC;

-- Archetype效果对比
CREATE VIEW v_archetype_performance AS
SELECT 
    archetype,
    COUNT(DISTINCT f.function_id) as function_count,
    COUNT(d.attempt_id) as total_attempts,
    SUM(CASE WHEN d.status = 'success' THEN 1 ELSE 0 END) as successes,
    ROUND(100.0 * SUM(CASE WHEN d.status = 'success' THEN 1 ELSE 0 END) / 
          NULLIF(COUNT(d.attempt_id), 0), 2) as success_rate,
    ROUND(AVG(CASE WHEN d.status = 'success' THEN d.coverage_percentage END), 2) 
        as avg_coverage
FROM functions f
LEFT JOIN driver_attempts d ON f.function_id = d.function_id
WHERE archetype IS NOT NULL
GROUP BY archetype
ORDER BY success_rate DESC;

-- 最有效的修复
CREATE VIEW v_top_fixes AS
SELECT 
    ft.fix_id,
    ep.error_type,
    ft.effectiveness_score,
    ft.reuse_count,
    ft.context_description,
    ft.created_at
FROM fix_transformations ft
JOIN error_patterns ep ON ft.error_pattern_id = ep.error_id
WHERE ft.effectiveness_score > 0.7
ORDER BY ft.reuse_count DESC, ft.effectiveness_score DESC
LIMIT 50;

-- 项目难度排名
CREATE VIEW v_project_difficulty AS
SELECT 
    p.project_name,
    COUNT(DISTINCT f.function_id) as function_count,
    ROUND(AVG(f.complexity_score), 3) as avg_complexity,
    ROUND(AVG(f.success_rate), 2) as avg_success_rate,
    ROUND(AVG(CASE WHEN d.status = 'success' THEN d.iteration END), 1) 
        as avg_iterations_to_success
FROM projects p
JOIN functions f ON p.project_id = f.project_id
LEFT JOIN driver_attempts d ON f.function_id = d.function_id
GROUP BY p.project_id
ORDER BY avg_success_rate ASC;
```

---

### Chroma向量数据库设计

```python
# 三个Collection，各司其职

# Collection 1: 成功的Driver代码
driver_codes_collection = {
    "name": "driver_codes",
    "metadata_schema": {
        "attempt_id": int,
        "function_name": str,
        "project": str,
        "archetype": str,
        "success": bool,
        "iteration": int,
        "coverage": float,
        "timestamp": str
    },
    "document": "完整的driver C/C++代码"
}

# Collection 2: 错误上下文（用于检索相似错误）
error_contexts_collection = {
    "name": "error_contexts",
    "metadata_schema": {
        "attempt_id": int,
        "error_type": str,
        "error_category": str,
        "function_name": str,
        "archetype": str,
        "fixed": bool,
        "fix_id": int  # 如果已修复，关联到fix_transformation
    },
    "document": "错误代码片段 + 错误消息 + 周围上下文"
}

# Collection 3: API使用代码片段
api_snippets_collection = {
    "name": "api_snippets",
    "metadata_schema": {
        "pattern_id": int,
        "function_name": str,
        "usage_type": str,
        "archetype": str,
        "confidence": float,
        "source": str
    },
    "document": "代码片段 + 注释说明"
}
```

---

## 🔧 API接口设计

### KnowledgeDatabase核心接口

```python
# knowledge_db/retriever.py

from typing import List, Dict, Optional, Any
import sqlite3
import chromadb
from pathlib import Path
from long_term_memory.retrieval import KnowledgeRetriever as LTMRetriever


class KnowledgeDatabase:
    """
    统一的知识库访问接口
    
    整合三层知识：
    1. SQLite（结构化数据、统计分析）
    2. Chroma（语义检索）
    3. long_term_memory（静态知识）
    """
    
    def __init__(
        self, 
        db_path: str = "knowledge_db/data/fuzzing_knowledge.db",
        vector_db_path: str = "knowledge_db/data/chroma_db"
    ):
        """初始化知识库连接"""
        self.sql_db = sqlite3.connect(db_path)
        self.sql_db.row_factory = sqlite3.Row  # 返回字典式结果
        
        self.vector_db = chromadb.PersistentClient(path=vector_db_path)
        self.driver_collection = self.vector_db.get_or_create_collection("driver_codes")
        self.error_collection = self.vector_db.get_or_create_collection("error_contexts")
        self.snippet_collection = self.vector_db.get_or_create_collection("api_snippets")
        
        self.ltm = LTMRetriever()  # 现有的long-term memory
        
    # ========================================================================
    # 检索方法（供Agent调用）
    # ========================================================================
    
    def find_similar_drivers(
        self, 
        function_info: Dict[str, Any],
        archetype: str = None,
        top_k: int = 3,
        min_success_rate: float = 0.0
    ) -> List[Dict[str, Any]]:
        """
        语义检索：找到最相似的成功driver案例
        
        Args:
            function_info: 包含 signature, name, header 等信息
            archetype: 指定archetype过滤
            top_k: 返回top-k个结果
            min_success_rate: 最低成功率过滤
            
        Returns:
            [
                {
                    "attempt_id": int,
                    "function_name": str,
                    "driver_code": str,
                    "archetype": str,
                    "coverage": float,
                    "similarity_score": float
                },
                ...
            ]
        """
        
    def get_error_fixes(
        self, 
        error_message: str,
        error_type: str = None,
        context: Dict[str, Any] = None,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        根据错误信息查找已知修复方案
        
        Args:
            error_message: 编译器/运行时错误信息
            error_type: 错误类型（如果已知）
            context: 上下文信息（function_name, archetype等）
            top_k: 返回top-k个修复
            
        Returns:
            [
                {
                    "fix_id": int,
                    "error_type": str,
                    "before_code": str,
                    "after_code": str,
                    "effectiveness_score": float,
                    "fix_strategy": str,
                    "reuse_count": int
                },
                ...
            ]
        """
        
    def get_api_usage_examples(
        self, 
        function_name: str,
        usage_context: str = None,  # 'initialization', 'main_call', 'cleanup'
        archetype: str = None,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        获取API的典型使用示例
        
        Args:
            function_name: 目标函数名
            usage_context: 用法上下文
            archetype: 限定archetype
            top_k: 返回数量
            
        Returns:
            [
                {
                    "pattern_id": int,
                    "code_snippet": str,
                    "explanation": str,
                    "usage_context": str,
                    "confidence": float,
                    "source": str
                },
                ...
            ]
        """
        
    def get_header_mapping(
        self, 
        function_name: str,
        project: str = None
    ) -> Dict[str, Any]:
        """
        获取函数的正确头文件路径
        
        Returns:
            {
                "header_path": str,
                "header_type": str,
                "depends_on": List[str],
                "common_mistakes": List[str]
            }
        """
        
    def get_archetype_knowledge(
        self, 
        archetype: str,
        include_stats: bool = True
    ) -> Dict[str, Any]:
        """
        获取特定archetype的完整知识
        
        整合：
        - long_term_memory的静态知识
        - 数据库中的统计信息
        - 最佳实践案例
        
        Returns:
            {
                "archetype_doc": str,  # from LTM
                "skeleton": str,  # from LTM
                "pitfalls": Dict[str, str],  # from LTM
                "stats": {
                    "success_rate": float,
                    "avg_coverage": float,
                    "common_errors": List[str]
                },
                "best_examples": List[Dict]
            }
        """
        
    # ========================================================================
    # 记录方法（供Workflow调用）
    # ========================================================================
    
    def record_driver_attempt(
        self,
        function_info: Dict[str, Any],
        driver_code: str,
        status: str,
        error_info: Dict[str, Any] = None,
        performance: Dict[str, Any] = None,
        metadata: Dict[str, Any] = None
    ) -> int:
        """
        记录一次driver生成尝试
        
        Args:
            function_info: 函数信息
            driver_code: 生成的driver代码
            status: 'success', 'compile_error', 'runtime_error', etc.
            error_info: 错误信息（如果失败）
            performance: 性能指标（如果成功）
            metadata: 额外元数据
            
        Returns:
            attempt_id
        """
        
    def learn_from_success(
        self,
        attempt_id: int,
        driver_code: str,
        metadata: Dict[str, Any]
    ):
        """
        从成功案例中学习
        
        操作：
        1. 更新SQLite统计
        2. 添加到向量数据库
        3. 提取可复用的代码片段
        """
        
    def learn_from_failure(
        self,
        attempt_id: int,
        error_info: Dict[str, Any],
        driver_code: str
    ):
        """
        从失败案例中学习
        
        操作：
        1. 提取错误模式
        2. 添加到错误数据库
        3. 标记需要修复
        """
        
    def record_fix_transformation(
        self,
        failed_attempt_id: int,
        success_attempt_id: int,
        before_code: str,
        after_code: str,
        fix_description: str
    ) -> int:
        """
        记录一次成功的修复转换
        
        Returns:
            fix_id
        """
        
    # ========================================================================
    # 统计分析方法
    # ========================================================================
    
    def get_global_stats(self) -> Dict[str, Any]:
        """
        获取全局统计信息
        
        Returns:
            {
                "total_attempts": int,
                "success_rate": float,
                "total_functions": int,
                "total_projects": int,
                "top_errors": List[Dict],
                "archetype_performance": Dict[str, float]
            }
        """
        
    def get_function_stats(self, function_name: str) -> Dict[str, Any]:
        """获取特定函数的历史统计"""
        
    def get_project_stats(self, project_name: str) -> Dict[str, Any]:
        """获取特定项目的统计"""
        
    def export_report(self, output_path: str):
        """导出完整的统计报告（JSON/HTML）"""
        
    # ========================================================================
    # 维护方法
    # ========================================================================
    
    def cleanup_duplicates(self):
        """清理重复的driver记录（基于hash）"""
        
    def update_statistics(self):
        """更新所有统计信息"""
        
    def optimize_vector_db(self):
        """优化向量数据库（重建索引等）"""


# ============================================================================
# 便捷函数
# ============================================================================

_global_kb: Optional[KnowledgeDatabase] = None

def get_knowledge_database() -> KnowledgeDatabase:
    """获取全局知识库实例（单例模式）"""
    global _global_kb
    if _global_kb is None:
        _global_kb = KnowledgeDatabase()
    return _global_kb


def reset_knowledge_database():
    """重置全局实例（主要用于测试）"""
    global _global_kb
    _global_kb = None
```

---

## 🔌 集成到LangGraph工作流

### 在Prototyper中集成

```python
# agent_graph/nodes/prototyper.py

from knowledge_db.retriever import get_knowledge_database

def prototyper_node(state: FuzzingWorkflowState) -> Dict[str, Any]:
    """Enhanced Prototyper with Knowledge Database"""
    
    # 1. 提取函数信息
    function_info = state.get("function_analysis", {})
    archetype = function_info.get("archetype")
    
    if not function_info:
        return {"errors": ["No function analysis available"]}
    
    # 2. 从知识库检索参考 🆕
    kb = get_knowledge_database()
    
    # 2a. 获取相似的成功driver
    similar_drivers = kb.find_similar_drivers(
        function_info=function_info,
        archetype=archetype,
        top_k=3,
        min_success_rate=0.7
    )
    
    # 2b. 获取API使用示例
    api_examples = kb.get_api_usage_examples(
        function_name=function_info.get("name"),
        archetype=archetype,
        top_k=5
    )
    
    # 2c. 获取archetype知识（整合LTM + 统计）
    archetype_bundle = kb.get_archetype_knowledge(
        archetype=archetype,
        include_stats=True
    )
    
    # 2d. 获取正确的header路径
    header_mapping = kb.get_header_mapping(
        function_name=function_info.get("name"),
        project=state.get("benchmark", {}).get("project")
    )
    
    # 3. 构建增强的prompt
    prompt = _build_enhanced_prototyper_prompt(
        specification=state.get("specification"),
        function_info=function_info,
        similar_drivers=similar_drivers,  # 🆕
        api_examples=api_examples,  # 🆕
        archetype_bundle=archetype_bundle,  # 🆕
        header_mapping=header_mapping,  # 🆕
        session_memory=state.get("session_memory", {})
    )
    
    # 4. 生成driver
    prototyper = get_prototyper_agent(...)
    response = prototyper.chat_llm(state, prompt)
    driver_code = parse_tag(response, 'fuzz target')
    
    # 5. 记录到知识库 🆕
    attempt_id = kb.record_driver_attempt(
        function_info=function_info,
        driver_code=driver_code,
        status="generated",
        metadata={
            "trial": state["trial"],
            "iteration": state["current_iteration"],
            "agent": "prototyper",
            "used_references": [d["attempt_id"] for d in similar_drivers]
        }
    )
    
    # 6. 更新state
    return {
        "fuzz_target_source": driver_code,
        "current_attempt_id": attempt_id,  # 🆕 追踪
        "used_knowledge": {
            "similar_drivers": len(similar_drivers),
            "api_examples": len(api_examples)
        }
    }


def _build_enhanced_prototyper_prompt(
    specification: str,
    function_info: Dict,
    similar_drivers: List[Dict],
    api_examples: List[Dict],
    archetype_bundle: Dict,
    header_mapping: Dict,
    session_memory: Dict
) -> str:
    """构建包含知识库参考的prompt"""
    
    prompt_parts = [
        "# Task: Generate Fuzz Driver",
        "",
        "## Specification",
        specification,
        "",
    ]
    
    # 添加相似driver参考
    if similar_drivers:
        prompt_parts.extend([
            "## Reference: Similar Successful Drivers",
            "",
            "Here are similar drivers that successfully compiled:",
            ""
        ])
        for i, driver in enumerate(similar_drivers, 1):
            prompt_parts.extend([
                f"### Reference {i}: {driver['function_name']} "
                f"(Coverage: {driver['coverage']:.1f}%)",
                "```c",
                driver['driver_code'],
                "```",
                ""
            ])
    
    # 添加API使用示例
    if api_examples:
        prompt_parts.extend([
            "## API Usage Examples",
            "",
            "Typical usage patterns for this API:",
            ""
        ])
        for ex in api_examples:
            prompt_parts.extend([
                f"**{ex['usage_context']}** (confidence: {ex['confidence']:.2f})",
                "```c",
                ex['code_snippet'],
                "```",
                f"_{ex['explanation']}_",
                ""
            ])
    
    # 添加正确的header信息
    if header_mapping:
        prompt_parts.extend([
            "## Correct Header Path",
            "",
            f"Use this exact header path: `{header_mapping['header_path']}`",
            ""
        ])
        if header_mapping.get('common_mistakes'):
            prompt_parts.extend([
                "**Do NOT use these wrong paths:**",
                *[f"- ❌ `{m}`" for m in header_mapping['common_mistakes']],
                ""
            ])
    
    # 添加archetype统计
    if archetype_bundle.get('stats'):
        stats = archetype_bundle['stats']
        prompt_parts.extend([
            f"## Archetype Statistics ({function_info.get('archetype')})",
            "",
            f"- Success rate: {stats.get('success_rate', 0):.1f}%",
            f"- Average coverage: {stats.get('avg_coverage', 0):.1f}%",
            f"- Common errors: {', '.join(stats.get('common_errors', [])[:3])}",
            ""
        ])
    
    # Session memory
    if session_memory:
        from agent_graph.state import format_session_memory_for_prompt
        prompt_parts.extend([
            "",
            format_session_memory_for_prompt({"session_memory": session_memory})
        ])
    
    prompt_parts.extend([
        "",
        "## Instructions",
        "Generate a fuzz driver using the above references as guidance.",
        "Follow the specification strictly and use the correct header paths.",
        ""
    ])
    
    return "\n".join(prompt_parts)
```

### 在Enhancer中集成

```python
# agent_graph/nodes/enhancer.py

from knowledge_db.retriever import get_knowledge_database

def enhancer_node(state: FuzzingWorkflowState) -> Dict[str, Any]:
    """Enhanced Enhancer with Error Fix Retrieval"""
    
    build_errors = state.get("build_errors", [])
    if not build_errors:
        return {}
    
    kb = get_knowledge_database()
    
    # 1. 对每个错误，查找已知修复
    all_known_fixes = []
    for error in build_errors:
        fixes = kb.get_error_fixes(
            error_message=error.get("message", ""),
            error_type=error.get("type"),
            context={
                "function": state["function_analysis"]["name"],
                "archetype": state["function_analysis"]["archetype"]
            },
            top_k=3
        )
        all_known_fixes.extend(fixes)
    
    # 2. 去重并排序（按effectiveness_score和reuse_count）
    unique_fixes = {f["fix_id"]: f for f in all_known_fixes}.values()
    sorted_fixes = sorted(
        unique_fixes, 
        key=lambda f: (f["effectiveness_score"], f["reuse_count"]),
        reverse=True
    )[:5]  # 最多5个修复建议
    
    # 3. 构建增强的修复prompt
    prompt = _build_enhanced_enhancer_prompt(
        current_code=state["fuzz_target_source"],
        errors=build_errors,
        known_fixes=sorted_fixes,  # 🆕
        session_memory=state.get("session_memory", {})
    )
    
    # 4. 生成修复
    enhancer = get_enhancer_agent(...)
    response = enhancer.chat_llm(state, prompt)
    fixed_code = parse_tag(response, 'fuzz target')
    
    # 5. 记录尝试
    failed_attempt_id = state.get("current_attempt_id")
    new_attempt_id = kb.record_driver_attempt(
        function_info=state["function_analysis"],
        driver_code=fixed_code,
        status="enhanced",
        metadata={
            "trial": state["trial"],
            "iteration": state["current_iteration"],
            "agent": "enhancer",
            "fixed_errors": [e.get("type") for e in build_errors],
            "used_fixes": [f["fix_id"] for f in sorted_fixes]
        }
    )
    
    return {
        "fuzz_target_source": fixed_code,
        "current_attempt_id": new_attempt_id,
        "previous_attempt_id": failed_attempt_id
    }


def _build_enhanced_enhancer_prompt(
    current_code: str,
    errors: List[Dict],
    known_fixes: List[Dict],
    session_memory: Dict
) -> str:
    """构建包含已知修复的prompt"""
    
    prompt_parts = [
        "# Task: Fix Compilation Errors",
        "",
        "## Current Code (with errors)",
        "```c",
        current_code,
        "```",
        "",
        "## Compilation Errors",
        ""
    ]
    
    for i, error in enumerate(errors, 1):
        prompt_parts.extend([
            f"### Error {i}: {error.get('type', 'Unknown')}",
            "```",
            error.get('message', ''),
            "```",
            ""
        ])
    
    # 添加已知修复
    if known_fixes:
        prompt_parts.extend([
            "## Known Fixes from Knowledge Base",
            "",
            "Similar errors have been fixed before. Here are proven solutions:",
            ""
        ])
        
        for i, fix in enumerate(known_fixes, 1):
            prompt_parts.extend([
                f"### Fix {i}: {fix['error_type']} "
                f"(Effectiveness: {fix['effectiveness_score']:.2f}, "
                f"Reused: {fix['reuse_count']} times)",
                "",
                "**Before (incorrect):**",
                "```c",
                fix['before_code'],
                "```",
                "",
                "**After (correct):**",
                "```c",
                fix['after_code'],
                "```",
                "",
                f"**Strategy:** {fix['fix_strategy']}",
                ""
            ])
    
    # Session memory
    if session_memory:
        from agent_graph.state import format_session_memory_for_prompt
        prompt_parts.extend([
            "",
            format_session_memory_for_prompt({"session_memory": session_memory})
        ])
    
    prompt_parts.extend([
        "",
        "## Instructions",
        "Fix the errors using the known fixes as reference.",
        "Apply similar transformations to the current code.",
        ""
    ])
    
    return "\n".join(prompt_parts)
```

### 在Build Node中记录结果

```python
# agent_graph/nodes/build.py

from knowledge_db.retriever import get_knowledge_database

def build_node(state: FuzzingWorkflowState) -> Dict[str, Any]:
    """Build node with knowledge recording"""
    
    # 编译driver
    result = compile_driver(
        source_code=state["fuzz_target_source"],
        work_dirs=state["work_dirs"],
        benchmark=state["benchmark"]
    )
    
    kb = get_knowledge_database()
    current_attempt_id = state.get("current_attempt_id")
    
    if result.success:
        # ✅ 成功：学习并记录
        kb.learn_from_success(
            attempt_id=current_attempt_id,
            driver_code=state["fuzz_target_source"],
            metadata={
                "function": state["function_analysis"]["name"],
                "archetype": state["function_analysis"]["archetype"],
                "project": state["benchmark"]["project"],
                "iteration": state["current_iteration"],
                "coverage": result.coverage if hasattr(result, 'coverage') else None
            }
        )
        
        # 如果是修复成功，记录transformation
        previous_attempt_id = state.get("previous_attempt_id")
        if previous_attempt_id and state.get("current_iteration", 0) > 1:
            kb.record_fix_transformation(
                failed_attempt_id=previous_attempt_id,
                success_attempt_id=current_attempt_id,
                before_code=state.get("previous_fuzz_target_source", ""),
                after_code=state["fuzz_target_source"],
                fix_description="Enhanced from compilation error"
            )
        
        logger.info(f"✅ Success recorded to knowledge base (attempt {current_attempt_id})")
        
    else:
        # ❌ 失败：记录错误
        kb.learn_from_failure(
            attempt_id=current_attempt_id,
            error_info={
                "type": result.error_type,
                "message": result.error_message,
                "category": "compilation",
                "log": result.build_log
            },
            driver_code=state["fuzz_target_source"]
        )
        
        logger.info(f"❌ Failure recorded to knowledge base (attempt {current_attempt_id})")
    
    return {
        "build_result": result,
        "build_errors": result.errors if not result.success else []
    }
```

---

## 📦 实施计划

### Phase 1: 基础架构（Week 1-2）

**目标**：建立基本的数据库和API

#### 任务清单
- [ ] 创建`knowledge_db/`目录结构
- [ ] 实现SQLite schema（`schema.sql`）
- [ ] 实现`KnowledgeDatabase`基础类
  - [ ] 数据库连接管理
  - [ ] 基础CRUD操作
  - [ ] 记录方法（`record_driver_attempt`等）
- [ ] 单元测试（基础功能）
- [ ] 集成到state中（添加`current_attempt_id`字段）

#### 验收标准
- ✅ SQLite数据库可创建并初始化
- ✅ 可以记录driver尝试
- ✅ 基础统计视图可查询
- ✅ 测试覆盖率 > 80%

---

### Phase 2: 向量检索（Week 3-4）

**目标**：添加语义检索能力

#### 任务清单
- [ ] 集成Chroma向量数据库
- [ ] 实现三个collection的管理
- [ ] 实现`find_similar_drivers()`
- [ ] 实现`get_error_fixes()`（语义检索版）
- [ ] 实现`get_api_usage_examples()`
- [ ] 向量数据库测试

#### 验收标准
- ✅ 可以将driver代码嵌入并存储
- ✅ 语义检索返回相关结果
- ✅ 相似度分数合理（> 0.7为相关）
- ✅ 检索速度 < 500ms

---

### Phase 3: 工作流集成（Week 5-6）

**目标**：集成到LangGraph各节点

#### 任务清单
- [ ] 修改`prototyper_node`
  - [ ] 调用`find_similar_drivers()`
  - [ ] 调用`get_api_usage_examples()`
  - [ ] 增强prompt构建
- [ ] 修改`enhancer_node`
  - [ ] 调用`get_error_fixes()`
  - [ ] 增强修复prompt
- [ ] 修改`build_node`
  - [ ] 记录编译结果
  - [ ] 学习成功/失败
  - [ ] 记录fix transformation
- [ ] 更新prompt模板

#### 验收标准
- ✅ Prototyper可以使用参考driver
- ✅ Enhancer可以使用已知修复
- ✅ 每次运行都记录到数据库
- ✅ 端到端测试通过

---

### Phase 4: 数据导入（Week 7）

**目标**：导入历史数据和OSS-Fuzz drivers

#### 任务清单
- [ ] 编写`bootstrap.py`脚本
  - [ ] 从`results/`目录导入历史记录
  - [ ] 解析成功/失败案例
- [ ] 编写`import_oss_fuzz.py`
  - [ ] 从OSS-Fuzz仓库导入成功drivers
  - [ ] 提取函数签名和archetype
- [ ] 从`long_term_memory`导入静态知识
- [ ] 数据清洗和去重

#### 验收标准
- ✅ 至少导入100个成功driver
- ✅ 导入50+个错误模式
- ✅ 数据质量检查通过
- ✅ 向量数据库索引完成

---

### Phase 5: 优化与监控（Week 8）

**目标**：性能优化和可观测性

#### 任务清单
- [ ] 添加查询性能监控
- [ ] 实现缓存机制（LRU cache）
- [ ] 数据库索引优化
- [ ] 实现`export_report()`统计报告
- [ ] 添加日志和metrics
- [ ] 创建维护脚本
  - [ ] `cleanup_duplicates.py`
  - [ ] `update_stats.py`
  - [ ] `backup_db.sh`

#### 验收标准
- ✅ 查询P95延迟 < 1s
- ✅ 可导出HTML统计报告
- ✅ 有日志追踪知识库使用情况
- ✅ 数据库大小可控（< 10GB）

---

## 📊 预期效果

### 量化指标

| 指标 | 当前 | 目标（3个月后） | 改进幅度 |
|------|------|----------------|---------|
| 首次成功率 | 35% | 50%+ | +43% |
| 平均迭代次数 | 4.2 | 2.5 | -40% |
| 重复错误率 | 60% | 20% | -67% |
| 修复时间 | 平均3轮 | 平均1.5轮 | -50% |
| Token消耗 | - | -30% | 减少重复推理 |

### 质量指标

- **参考质量**：提供高相似度（> 0.8）的参考driver
- **修复准确性**：已知错误的修复成功率 > 80%
- **知识积累**：每周增长 50+ 条有效知识
- **长期改进**：成功率随时间持续提升

---

## 🔒 注意事项

### 数据隐私
- 所有代码均为开源项目
- 不包含敏感信息
- 可本地部署，无需外部API

### 存储管理
- SQLite单文件，易于备份
- 定期清理重复记录
- 向量数据库可压缩

### 性能考虑
- 查询缓存（LRU）
- 异步记录（避免阻塞主流程）
- 批量插入优化

### 可维护性
- 清晰的schema文档
- 版本控制（schema migration）
- 测试覆盖

---

## 📚 参考资源

- **SQLite FTS5**: https://www.sqlite.org/fts5.html
- **Chroma文档**: https://docs.trychroma.com/
- **Embedding模型**: OpenAI API / HuggingFace Transformers
- **相似项目**: 
  - CodeSearchNet（代码检索）
  - BigCode Project（代码生成）

---

## 🎯 总结

这个知识库设计的核心价值在于：

1. **持久化学习** - 从每次运行中积累经验
2. **精准参考** - 语义检索找到最相关的案例
3. **快速修复** - 已知错误直接应用修复方案
4. **数据驱动** - 统计分析指导系统优化

它与现有的两层知识（`long_term_memory`静态知识 + `session_memory`临时状态）形成完美互补：

```
Static Knowledge (通用) → Session Memory (单次) → Persistent KB (跨运行)
     ↓                          ↓                        ↓
  指导设计                   追踪状态                  经验积累
```

这将显著提升driver生成的成功率和效率。

---

**版本**: 1.0  
**日期**: 2025-10-30  
**作者**: OSS-Fuzz-Gen Team  
**状态**: 设计完成，待实施

