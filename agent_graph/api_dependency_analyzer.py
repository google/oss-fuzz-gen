#!/usr/bin/env python3
"""
API Dependency Analyzer - 基于 Tree-sitter 和 FuzzIntrospector

从现有的 tree-sitter 和 FuzzIntrospector 基础设施构建 API 依赖图，
用于指导 LLM 生成正确的 API 调用序列。

核心功能：
1. 识别前置依赖（初始化函数）
2. 分析数据流依赖（参数来源）
3. 构建调用图
4. 生成正确的调用顺序

使用方法：
    from agent_graph.api_dependency_analyzer import APIDependencyAnalyzer
    
    analyzer = APIDependencyAnalyzer(
        project_name="igraph",
        project_dir="/path/to/src"
    )
    
    dep_graph = analyzer.build_dependency_graph("target_function")
    print(dep_graph["call_sequence"])  # 正确的调用顺序
"""

import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from data_prep import introspector
from agent_graph.api_context_extractor import APIContextExtractor
from agent_graph.api_heuristics import (
    INIT_SUFFIXES,
    CLEANUP_SUFFIXES,
    clean_type_name,
    is_primitive_type,
    get_base_name_from_type
)

# 尝试导入 networkx
try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    # Fallback: 使用简单的邻接表
    class SimpleGraph:
        """简单的有向图实现（无 networkx 时的 fallback）"""
        def __init__(self):
            self.nodes = {}
            self.edges = []
        
        def add_node(self, node, **attrs):
            self.nodes[node] = attrs
        
        def add_edge(self, src, dst, **attrs):
            self.edges.append((src, dst, attrs))
        
        def get_nodes(self):
            return list(self.nodes.keys())
        
        def topological_sort_dfs(self):
            """简单的拓扑排序实现"""
            # 构建邻接表
            graph = {}
            in_degree = {}
            for node in self.nodes:
                graph[node] = []
                in_degree[node] = 0
            
            for src, dst, _ in self.edges:
                graph[src].append(dst)
                in_degree[dst] = in_degree.get(dst, 0) + 1
            
            # Kahn's algorithm
            queue = [n for n in self.nodes if in_degree[n] == 0]
            result = []
            
            while queue:
                node = queue.pop(0)
                result.append(node)
                for neighbor in graph[node]:
                    in_degree[neighbor] -= 1
                    if in_degree[neighbor] == 0:
                        queue.append(neighbor)
            
            return result if len(result) == len(self.nodes) else list(self.nodes.keys())

logger = logging.getLogger(__name__)


class APIDependencyAnalyzer:
    """
    基于现有的 tree-sitter + FuzzIntrospector 构建依赖图
    
    支持两种模式：
    1. Heuristic mode (默认): 使用启发式规则快速分析
    2. LLM mode: 使用 LLM 进行深度分析（需要提供 llm 参数）
    """
    
    def __init__(
        self, 
        project_name: str, 
        project_dir: str = "",
        llm: Optional[any] = None,
        use_llm: bool = False
    ):
        self.project_name = project_name
        self.project_dir = project_dir
        self.llm = llm
        self.use_llm = use_llm and llm is not None
        
        # 使用 networkx 或 fallback
        if HAS_NETWORKX:
            self.graph = nx.DiGraph()
        else:
            self.graph = SimpleGraph()
            logger.warning("networkx not available, using simple graph implementation")
        
        self.extractor = APIContextExtractor(project_name)
        self._all_functions_cache: Optional[Set[str]] = None
        
        # Initialize LLM analyzer if requested
        self._llm_analyzer = None
        if self.use_llm:
            self._initialize_llm_analyzer()
    
    def _initialize_llm_analyzer(self):
        """初始化 LLM 分析器"""
        try:
            from agent_graph.llm_api_analyzer import LLMAPIDependencyAnalyzer, load_prompts
            
            system_prompt, user_prompt_template = load_prompts()
            self._llm_analyzer = LLMAPIDependencyAnalyzer(
                project_name=self.project_name,
                llm=self.llm,
                system_prompt=system_prompt,
                user_prompt_template=user_prompt_template
            )
            logger.info(f"✨ LLM-based API dependency analysis enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize LLM analyzer: {e}. Falling back to heuristics.")
            self.use_llm = False
    
    def build_dependency_graph(self, target_function: str) -> Dict:
        """
        构建目标函数的局部依赖图
        
        Args:
            target_function: 目标函数名（如 "igraph_sparsemat_arpack_rssolve"）
        
        Returns:
            包含以下字段的字典：
            - prerequisites: 必须先调用的初始化函数列表
            - data_dependencies: 参数依赖关系 [(producer, consumer), ...]
            - call_sequence: 推荐的调用顺序
            - initialization_code: 建议的初始化代码模板
            - llm_metadata: (if LLM mode) 额外的 LLM 分析信息
            
        Note: 
            The internal DiGraph object is not included in the result to avoid
            serialization issues with LangGraph's msgpack checkpointer.
        """
        logger.info(f"Building dependency graph for {target_function}")
        
        # Use LLM analysis if enabled
        if self.use_llm and self._llm_analyzer:
            return self._build_with_llm(target_function)
        
        # Otherwise use heuristic approach
        # 1. 使用 FuzzIntrospector 获取函数上下文
        context = self.extractor.extract(target_function)
        if not context:
            logger.warning(f"Could not extract context for {target_function}")
            return {
                'prerequisites': [],
                'data_dependencies': [],
                'call_sequence': [],
                'initialization_code': []
            }
        
        # 2. 识别前置依赖（init 函数）
        prerequisites = self._find_prerequisite_functions(target_function, context)
        
        # 3. 识别数据流依赖（参数来源）
        data_deps = self._analyze_data_dependencies(target_function, context)
        
        # 4. 构建图
        self.graph.add_node(target_function, type='target', context=context)
        for prereq in prerequisites:
            self.graph.add_node(prereq, type='prerequisite')
            self.graph.add_edge(prereq, target_function, type='control')
        
        for src, dst in data_deps:
            self.graph.add_node(src, type='producer')
            self.graph.add_edge(src, dst, type='data')
        
        # 5. 生成调用顺序
        call_sequence = self._generate_call_sequence()
        
        # 6. 生成初始化代码模板
        init_code = self._generate_initialization_code(target_function, context, prerequisites)
        
        logger.info(
            f"Dependency graph built: {len(prerequisites)} prerequisites, "
            f"{len(data_deps)} data deps, sequence: {call_sequence}"
        )
        
        return {
            'prerequisites': prerequisites,
            'data_dependencies': data_deps,
            'call_sequence': call_sequence,
            'initialization_code': init_code
        }
    
    def _build_with_llm(self, target_function: str) -> Dict:
        """
        使用 LLM 构建依赖图（增强模式）
        
        This provides richer, more context-aware dependency analysis
        by leveraging LLM reasoning over cross-references and usage patterns.
        """
        logger.info(f"🤖 Using LLM-based analysis for {target_function}")
        
        # Get LLM analysis (may return None on failure)
        llm_analysis = self._llm_analyzer.analyze_dependencies(target_function)
        
        if not llm_analysis:
            logger.warning("LLM analysis failed, falling back to heuristics")
            self.use_llm = False  # Disable for subsequent calls
            return self.build_dependency_graph(target_function)
        
        # Convert to legacy format
        result = self._llm_analyzer.convert_to_legacy_format(llm_analysis, target_function)
        
        # Log confidence note if available
        if confidence_note := result.get('llm_metadata', {}).get('confidence_note'):
            logger.info(f"🔍 {confidence_note}")
        
        return result
    
    def _find_prerequisite_functions(
        self, 
        func: str, 
        context: Dict
    ) -> List[str]:
        """
        使用启发式规则 + FuzzIntrospector 查找必须先调用的初始化函数
        """
        prerequisites = []
        
        # 从 initialization_patterns 中提取
        for pattern in context.get('initialization_patterns', []):
            param_type = pattern['type']
            base_name = get_base_name_from_type(param_type)
            
            # 检查是否存在 base_name_init/create/new
            for suffix in INIT_SUFFIXES:
                init_func = base_name + suffix
                if self._function_exists(init_func):
                    prerequisites.append(init_func)
                    logger.debug(f"Found prerequisite: {init_func} for type {param_type}")
                    break
        
        # 从 related_functions 中提取
        for related in context.get('related_functions', []):
            if related['type'] == 'initialization':
                func_name = related['name']
                if func_name not in prerequisites:
                    prerequisites.append(func_name)
        
        return prerequisites
    
    def _analyze_data_dependencies(
        self, 
        func: str, 
        context: Dict
    ) -> List[Tuple[str, str]]:
        """
        分析哪些参数必须来自其他函数的返回值
        
        策略：
        1. 对于复杂类型（非基本类型），查找生产者函数
        2. 使用 FuzzIntrospector 的类型信息
        """
        deps = []
        
        for param in context.get('parameters', []):
            param_type = clean_type_name(param['type'])
            param_name = param['name']
            
            # 跳过基本类型
            if is_primitive_type(param_type):
                continue
            
            # 查找生产者函数（返回该类型的函数）
            producer = self._find_producer_function(param_type)
            if producer:
                deps.append((producer, func))
                logger.debug(f"Found data dependency: {producer} -> {func} (type: {param_type})")
        
        return deps
    
    def _find_producer_function(self, type_name: str) -> Optional[str]:
        """
        查找返回给定类型的函数（通常是构造器）
        
        启发式规则：
        1. base_name_create/new/alloc
        2. 查询 FuzzIntrospector 获取返回该类型的函数
        """
        base = get_base_name_from_type(type_name)
        
        # 规则 1: 常见的构造器命名模式
        for suffix in INIT_SUFFIXES:
            candidate = base + suffix
            if self._function_exists(candidate):
                return candidate
        
        # 规则 2: 使用 FuzzIntrospector 查询（如果 API 支持）
        # TODO: FuzzIntrospector 有 query_introspector_matching_function_constructor_type
        # 但这是为 Java 设计的，需要检查 C/C++ 支持
        
        return None
    
    def _generate_call_sequence(self) -> List[str]:
        """
        拓扑排序生成正确的调用顺序
        """
        try:
            if HAS_NETWORKX:
                return list(nx.topological_sort(self.graph))
            else:
                return self.graph.topological_sort_dfs()
        except Exception as e:
            logger.warning(f"Topological sort failed: {e}, using simple order")
            # 如果有环或其他问题，返回简单顺序
            if HAS_NETWORKX:
                return list(self.graph.nodes())
            else:
                return self.graph.get_nodes()
    
    def _generate_initialization_code(
        self, 
        target_func: str,
        context: Dict, 
        prerequisites: List[str]
    ) -> List[str]:
        """
        生成初始化代码模板
        
        Returns:
            代码片段列表，每个元素是一行初始化代码
        """
        code_lines = []
        
        if not prerequisites and not context.get('initialization_patterns'):
            return code_lines
        
        code_lines.append("// Initialize required data structures")
        
        # 为每个初始化模式生成代码
        for pattern in context.get('initialization_patterns', []):
            param_type = pattern['type']
            param_name = pattern['parameter']
            method = pattern.get('method', '')
            
            # 生成变量声明
            code_lines.append(f"{param_type} {param_name};")
            
            # 生成初始化调用
            if method:
                # 替换占位符
                init_code = method.replace('&var', f'&{param_name}')
                init_code = init_code.replace('var', param_name)
                code_lines.append(init_code + ";")
            else:
                # 默认：使用 memset
                code_lines.append(f"memset(&{param_name}, 0, sizeof({param_type}));")
        
        # 为 prerequisites 生成调用
        for prereq in prerequisites:
            code_lines.append(f"// Call prerequisite: {prereq}")
            code_lines.append(f"{prereq}(...);  // TODO: Fill in parameters")
        
        return code_lines
    
    def _ensure_function_cache(self):
        """Lazy load function cache once"""
        if self._all_functions_cache is not None:
            return
        
        try:
            all_funcs = introspector.query_introspector_all_functions(self.project_name)
            # Collect all possible name variations
            names = set()
            for f in all_funcs:
                for key in ['function_signature', 'function-name', 'raw_function_name']:
                    if name := f.get(key):
                        names.add(name)
                        # Also add simple name extracted from signature
                        if '(' in name:
                            simple = re.search(r'\b([a-zA-Z_]\w*)\s*\(', name)
                            if simple:
                                names.add(simple.group(1))
            
            self._all_functions_cache = names
            logger.debug(f"Cached {len(names)} function names")
        except Exception as e:
            logger.debug(f"Could not load function cache: {e}")
            self._all_functions_cache = set()
    
    def _function_exists(self, func_name: str) -> bool:
        """Check if function exists (cached)"""
        self._ensure_function_cache()
        return func_name in self._all_functions_cache


def format_dependency_graph_for_prompt(dep_graph: Dict, target_function: str) -> str:
    """
    将依赖图格式化为适合注入 prompt 的文本
    
    Args:
        dep_graph: build_dependency_graph() 返回的字典
        target_function: 目标函数名
    
    Returns:
        格式化的 Markdown 文本
    """
    if not dep_graph:
        return ""
    
    sections = []
    sections.append("## 🔗 API Dependency Analysis\n")
    
    # Check if this is LLM-enhanced analysis
    llm_metadata = dep_graph.get('llm_metadata', {})
    is_llm_enhanced = bool(llm_metadata)
    
    if is_llm_enhanced:
        sections.append("**Source**: LLM-enhanced analysis (high confidence)\n")
        if llm_metadata.get('confidence_note'):
            sections.append(f"**Note**: {llm_metadata['confidence_note']}\n")
    
    # 1. 调用顺序
    if dep_graph.get('call_sequence'):
        sections.append("### ✅ Recommended Call Sequence\n")
        sections.append("**IMPORTANT**: Follow this order to ensure correct API usage:\n")
        for i, func in enumerate(dep_graph['call_sequence'], 1):
            if func == target_function:
                sections.append(f"{i}. **`{func}`** ← TARGET FUNCTION")
            else:
                sections.append(f"{i}. `{func}`")
        sections.append("")
    
    # 2. 前置依赖（初始化）
    if dep_graph.get('prerequisites'):
        sections.append("### ⚠️ Prerequisites (Initialization)\n")
        sections.append("These functions **MUST** be called before the target function:\n")
        for prereq in dep_graph['prerequisites']:
            sections.append(f"- `{prereq}()` - Initialize required resources")
        sections.append("")
    
    # 3. LLM-enhanced: Configuration functions
    if is_llm_enhanced and llm_metadata.get('configuration_functions'):
        sections.append("### ⚙️ Configuration Functions\n")
        sections.append("Use these to configure objects before calling the target:\n")
        for config_func in llm_metadata['configuration_functions']:
            sections.append(f"- `{config_func}()` - Set options/parameters")
        sections.append("")
    
    # 4. LLM-enhanced: Complementary functions
    if is_llm_enhanced and llm_metadata.get('complementary_functions'):
        sections.append("### 📤 Complementary Functions (Post-processing)\n")
        sections.append("Consider calling these after the target to query results:\n")
        for comp_func in llm_metadata['complementary_functions']:
            sections.append(f"- `{comp_func}()` - Get status/results")
        sections.append("")
    
    # 5. LLM-enhanced: Cleanup functions
    if is_llm_enhanced and llm_metadata.get('cleanup_functions'):
        sections.append("### 🧹 Cleanup Functions\n")
        sections.append("Call these to free resources (in reverse order):\n")
        for cleanup_func in llm_metadata['cleanup_functions']:
            sections.append(f"- `{cleanup_func}()` - Free resources")
        sections.append("")
    
    # 6. 数据依赖
    if dep_graph.get('data_dependencies'):
        sections.append("### 📊 Data Flow Dependencies\n")
        for src, dst in dep_graph['data_dependencies']:
            sections.append(f"- `{src}` produces data consumed by `{dst}`")
        sections.append("")
    
    # 7. 初始化代码模板
    if dep_graph.get('initialization_code'):
        sections.append("### 💡 Initialization Code Template\n")
        sections.append("```c")
        sections.extend(dep_graph['initialization_code'])
        sections.append("```\n")
    
    # 8. LLM call pattern example (if available)
    if is_llm_enhanced and llm_metadata.get('has_call_pattern'):
        sections.append("### 📝 Complete Usage Pattern\n")
        sections.append("```c")
        # Extract from initialization_code (which contains the call pattern)
        for line in dep_graph.get('initialization_code', []):
            if line.startswith('//'):
                sections.append(line.replace('// ', ''))
        sections.append("```\n")
    
    return "\n".join(sections)


def get_api_dependencies(project_name: str, target_function: str) -> Optional[Dict]:
    """
    便捷函数：获取函数的 API 依赖图
    
    Args:
        project_name: 项目名称（如 "igraph"）
        target_function: 目标函数签名
    
    Returns:
        依赖图字典，如果构建失败则返回 None
    """
    try:
        analyzer = APIDependencyAnalyzer(project_name)
        dep_graph = analyzer.build_dependency_graph(target_function)
        return dep_graph if dep_graph['call_sequence'] else None
    except Exception as e:
        logger.error(f"Failed to get API dependencies: {e}", exc_info=True)
        return None


if __name__ == "__main__":
    # 测试
    import sys
    logging.basicConfig(level=logging.DEBUG)
    
    if len(sys.argv) < 3:
        print("Usage: python api_dependency_analyzer.py <project_name> <function_name>")
        sys.exit(1)
    
    project = sys.argv[1]
    func = sys.argv[2]
    
    # 设置 FuzzIntrospector endpoint
    from data_prep.introspector import set_introspector_endpoints, DEFAULT_INTROSPECTOR_ENDPOINT
    set_introspector_endpoints(DEFAULT_INTROSPECTOR_ENDPOINT)
    
    analyzer = APIDependencyAnalyzer(project)
    result = analyzer.build_dependency_graph(func)
    
    print("\n" + "="*60)
    print(format_dependency_graph_for_prompt(result, func))
    print("="*60)

