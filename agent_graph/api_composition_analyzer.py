#!/usr/bin/env python3
"""
API Composition Analyzer

分析可以组合一起测试的API，而不是API依赖关系。
从真实使用场景和文档中识别API组合模式。
"""

import os
import sys

# Add project root to Python path
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

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


class APICompositionAnalyzer:
    """
    分析可以组合一起测试的API
    
    核心功能：
    1. 从usage examples中提取真实的API组合模式（而不是基于函数名模式猜测）
    2. 识别完整的API组合：包括配置、使用、清理等，而不仅仅是初始化函数
    3. 减少启发式规则依赖：只在完全没有usage examples时才使用fallback
    
    支持两种模式：
    1. Heuristic mode (默认): 基于真实代码使用模式分析
    2. LLM mode: 使用 LLM 进行深度分析（需要提供 llm 参数）
    
    分析策略（按优先级）：
    1. 从usage examples中提取真实的API组合模式（最可靠）
    2. 从related_functions中提取（作为补充）
    3. 启发式规则（仅在完全没有usage examples时使用，作为最后手段）
    """
    
    def __init__(
        self, 
        project_name: str, 
        project_dir: str = "",
        llm: Optional['any'] = None,  # Using string literal to avoid import issues
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
            from agent_graph.llm_api_analyzer import LLMAPIDependencyAnalyzer
            from agent_graph.prompt_loader import get_prompt_manager
            
            prompt_manager = get_prompt_manager()
            system_prompt = prompt_manager.get_system_prompt("api_dependency_analyzer")
            user_prompt_template = prompt_manager.get_user_prompt_template("api_dependency_analyzer")
            
            self._llm_analyzer = LLMAPIDependencyAnalyzer(
                project_name=self.project_name,
                llm=self.llm,
                system_prompt=system_prompt,
                user_prompt_template=user_prompt_template
            )
            logger.info(f"✨ LLM-based API composition analysis enabled")
        except Exception as e:
            logger.warning(f"Failed to initialize LLM analyzer: {e}. Falling back to heuristics.")
            self.use_llm = False
    
    def find_api_combinations(self, target_function: str, api_context: Optional[Dict] = None) -> Dict:
        """
        查找可以与目标函数组合一起测试的API
        
        优先从usage examples中提取真实的API组合模式，而不是基于函数名模式的猜测。
        识别完整的API组合：包括配置、使用、清理等，而不仅仅是初始化函数。
        
        Args:
            target_function: 目标函数名（如 "igraph_sparsemat_arpack_rssolve"）
            api_context: (Optional) 预先提取的 API context，避免重复查询 FuzzIntrospector
        
        Returns:
            包含以下字段的字典：
            - prerequisites: 与目标函数组合使用的API列表（从真实代码中提取）
            - data_dependencies: 参数依赖关系 [(producer, consumer), ...]
            - call_sequence: 推荐的API组合调用顺序（基于真实使用场景）
            - initialization_code: 建议的初始化代码模板
            - llm_metadata: (if LLM mode) 额外的 LLM 分析信息
            
        Note: 
            The internal DiGraph object is not included in the result to avoid
            serialization issues with LangGraph's msgpack checkpointer.
        """
        logger.info(f"Finding API combinations for {target_function}")
        
        # Use LLM analysis if enabled
        if self.use_llm and self._llm_analyzer:
            return self._build_with_llm(target_function)
        
        # Otherwise use heuristic approach
        # 1. 使用 FuzzIntrospector 获取函数上下文（或使用提供的 api_context）
        if api_context:
            logger.debug(f"Using provided api_context (avoiding redundant FI query)")
            context = api_context
        else:
            logger.debug(f"No api_context provided, querying FuzzIntrospector")
            context = self.extractor.extract(target_function)
        
        if not context:
            logger.warning(f"Could not extract context for {target_function}")
            return {
                'prerequisites': [],
                'data_dependencies': [],
                'call_sequence': [],
                'initialization_code': []
            }
        
        # 2. 识别前置依赖（API组合）- 优先从usage examples中提取真实使用模式
        prerequisites = self._find_prerequisite_functions(target_function, context)
        
        # 3. 识别数据流依赖（参数来源）
        data_deps = self._analyze_data_dependencies(target_function, context)
        
        # 3.5. 从 usage examples 中提取完整的API组合调用序列（核心改进）
        # 这提取了真实代码中与目标函数一起使用的完整API集合
        usage_call_sequence = self._extract_call_sequence_from_usage_examples(target_function, context)
        if usage_call_sequence:
            logger.info(f"✓ Extracted complete API combination sequence from usage examples: {len(usage_call_sequence)} APIs")
        
        # 4. 构建图
        self.graph.add_node(target_function, type='target', context=context)
        for prereq in prerequisites:
            self.graph.add_node(prereq, type='prerequisite')
            self.graph.add_edge(prereq, target_function, type='control')
        
        for src, dst in data_deps:
            self.graph.add_node(src, type='producer')
            self.graph.add_edge(src, dst, type='data')
        
        # 5. 生成调用顺序（优先使用从 usage examples 提取的序列）
        if usage_call_sequence:
            # 使用从 usage examples 中提取的完整序列
            call_sequence = usage_call_sequence
            logger.debug(f"Using call sequence from usage examples: {call_sequence}")
        else:
            # Fallback: 使用拓扑排序
            call_sequence = self._generate_call_sequence()
        
        # 6. 生成初始化代码模板
        init_code = self._generate_initialization_code(target_function, context, prerequisites)
        
        logger.info(
            f"API combinations found: {len(prerequisites)} combined APIs, "
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
        使用 LLM 分析API组合（增强模式）
        
        This provides richer, more context-aware API composition analysis
        by leveraging LLM reasoning over cross-references and usage patterns.
        """
        logger.info(f"🤖 Using LLM-based analysis for {target_function}")
        
        # Get LLM analysis (may return None on failure)
        llm_analysis = self._llm_analyzer.analyze_dependencies(target_function)
        
        if not llm_analysis:
            logger.warning("LLM analysis failed, falling back to heuristics")
            self.use_llm = False  # Disable for subsequent calls
            return self.find_api_combinations(target_function)
        
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
        查找必须与目标函数组合使用的API集合
        
        策略（按优先级）：
        1. 从 usage examples 中提取真实的API组合模式（最可靠，基于真实使用场景）
        2. 从 related_functions 中提取（作为补充）
        3. 使用启发式规则（仅在完全没有usage examples时使用，作为最后手段）
        
        注意：优先使用真实代码中的使用模式，而不是基于函数名模式的猜测
        """
        prerequisites = []
        
        # 策略 1: 从 usage examples 中提取真实的API组合模式（最高优先级）
        usage_based_prereqs = self._extract_prerequisites_from_usage_examples(func, context)
        if usage_based_prereqs:
            prerequisites.extend(usage_based_prereqs)
            logger.info(f"✓ Found {len(usage_based_prereqs)} prerequisite APIs from real-world usage examples")
        
        # 策略 2: 从 related_functions 中提取（作为补充信息）
        # 注意：只添加不在prerequisites中的函数，避免重复
        for related in context.get('related_functions', []):
            if related['type'] == 'initialization':
                func_name = related['name']
                if func_name not in prerequisites:
                    prerequisites.append(func_name)
                    logger.debug(f"Added prerequisite from related_functions: {func_name}")
        
        # 策略 3: 启发式规则（仅在完全没有usage examples时使用，作为最后手段）
        # 这是一个fallback，不应该作为主要方法
        if not prerequisites and not context.get('usage_examples'):
            logger.warning("No usage examples available, falling back to heuristics (less reliable)")
            heuristic_prereqs = self._find_prerequisites_heuristic(func, context)
            prerequisites.extend(heuristic_prereqs)
            if heuristic_prereqs:
                logger.debug(f"Found {len(heuristic_prereqs)} prerequisites using heuristics (fallback only)")
        elif not prerequisites:
            logger.warning(f"Usage examples exist but no prerequisites extracted - this may indicate the function has no dependencies")
        
        return prerequisites
    
    def _extract_prerequisites_from_usage_examples(
        self,
        target_func: str,
        context: Dict
    ) -> List[str]:
        """
        从 usage examples 中提取前置依赖（API组合模式）
        
        改进策略：
        1. 提取所有函数调用（不仅仅是初始化函数）
        2. 找到目标函数的位置
        3. 提取在目标函数之前调用的所有API（真实使用场景中的组合）
        4. 统计频率，找出最常见的API组合模式
        5. 保留调用顺序，返回按频率排序的API列表
        
        不再依赖启发式规则判断"初始化函数"，而是基于真实代码中的使用模式
        """
        usage_examples = context.get('usage_examples', [])
        if not usage_examples:
            return []
        
        # 提取简单函数名（用于匹配）
        target_func_simple = self._extract_function_name(target_func)
        if not target_func_simple:
            target_func_simple = target_func.split('(')[0].strip()
        
        # 收集所有示例中的调用序列
        all_call_sequences = []
        
        for example in usage_examples:
            source_code = example.get('source', '')
            if not source_code:
                continue
            
            # 提取函数调用序列
            calls = self._extract_function_calls_from_code(source_code)
            if not calls:
                continue
            
            # 找到目标函数的位置
            target_pos = self._find_function_in_calls(calls, target_func_simple)
            if target_pos is None:
                # 如果找不到目标函数，跳过这个示例
                continue
            
            # 提取目标函数之前的所有API调用（不仅仅是初始化函数）
            prereqs = []
            for i in range(target_pos):
                func_name = self._normalize_function_name(calls[i])
                # 只保留项目中真实存在的API函数（避免误匹配）
                if self._function_exists(func_name):
                    prereqs.append(func_name)
            
            if prereqs:
                all_call_sequences.append(prereqs)
                logger.debug(f"Found {len(prereqs)} API calls before {target_func_simple} in example")
        
        if not all_call_sequences:
            return []
        
        # 统计所有API函数的出现频率（不仅仅是初始化函数）
        api_func_counts = {}
        for sequence in all_call_sequences:
            for func_name in sequence:
                api_func_counts[func_name] = api_func_counts.get(func_name, 0) + 1
        
        # 按频率排序，返回最常见的API组合
        sorted_apis = sorted(
            api_func_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # 返回频率 >= 1 的函数（至少在一个示例中出现）
        # 这些是真实使用场景中与目标函数组合使用的API
        result = [func for func, count in sorted_apis if count >= 1]
        
        if result:
            logger.info(f"✓ Extracted {len(result)} prerequisite APIs from usage examples (real-world patterns): {result}")
        
        return result
    
    def _extract_function_calls_from_code(self, code: str) -> List[str]:
        """
        从代码中提取函数调用
        
        使用正则表达式匹配常见的函数调用模式：
        - func_name(...)
        - func_name ( ... )
        - obj->method(...)
        - obj.method(...)
        """
        import re
        
        # 匹配函数调用：identifier(...) 或 identifier ( ... )
        # 排除关键字、类型名等
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*\([^)]*\)'
        
        matches = re.findall(pattern, code)
        
        # 过滤掉常见的关键字和类型
        excluded = {
            'if', 'while', 'for', 'switch', 'return', 'sizeof',
            'malloc', 'free', 'calloc', 'realloc',  # 这些是通用的，不是 API 特定的
        }
        
        # 过滤掉太短的名称（可能是变量）
        filtered = [
            m for m in matches
            if m not in excluded and len(m) > 2
        ]
        
        return filtered
    
    def _find_function_in_calls(self, calls: List[str], target_func: str) -> Optional[int]:
        """
        在调用列表中查找目标函数的位置
        
        支持模糊匹配（处理函数名变体）
        """
        target_lower = target_func.lower()
        
        for i, call in enumerate(calls):
            call_lower = call.lower()
            # 精确匹配
            if call_lower == target_lower:
                return i
            # 部分匹配（处理命名空间前缀）
            if call_lower.endswith('_' + target_lower) or target_lower in call_lower:
                return i
        
        return None
    
    def _normalize_function_name(self, func_call: str) -> str:
        """
        规范化函数名（移除可能的参数信息）
        """
        # 移除可能的参数部分
        if '(' in func_call:
            return func_call.split('(')[0].strip()
        return func_call.strip()
    
    def _is_initialization_function(self, func_name: str) -> bool:
        """
        判断函数是否是初始化函数（已弃用，保留用于向后兼容）
        
        注意：这个方法现在主要用于向后兼容。新的实现应该基于
        usage examples中的真实使用模式，而不是函数名模式匹配。
        """
        func_lower = func_name.lower()
        
        # 检查是否包含初始化后缀
        has_init_suffix = any(
            func_lower.endswith(suffix) or suffix in func_lower
            for suffix in INIT_SUFFIXES
        )
        
        if not has_init_suffix:
            return False
        
        # 验证函数确实存在（避免误匹配）
        return self._function_exists(func_name)
    
    def _find_prerequisites_heuristic(
        self,
        func: str,
        context: Dict
    ) -> List[str]:
        """
        使用启发式规则查找前置依赖（fallback 方法）
        """
        prerequisites = []
        
        # 从 initialization_patterns 中提取
        for pattern in context.get('initialization_patterns', []):
            param_type = pattern['type']
            base_name = get_base_name_from_type(param_type)
            
            # 策略 1: 直接匹配 base_name + suffix
            found = False
            for suffix in INIT_SUFFIXES:
                init_func = base_name + suffix
                if self._function_exists(init_func):
                    prerequisites.append(init_func)
                    logger.debug(f"Found prerequisite (heuristic): {init_func} for type {param_type}")
                    found = True
                    break
            
            # 策略 2: 模糊匹配（如果直接匹配失败）
            if not found:
                fuzzy_matches = self._fuzzy_match_init_function(base_name)
                if fuzzy_matches:
                    prerequisites.extend(fuzzy_matches[:1])  # 只取第一个匹配
                    logger.debug(f"Found prerequisite (fuzzy): {fuzzy_matches[0]} for type {param_type}")
        
        return prerequisites
    
    def _fuzzy_match_init_function(self, base_name: str) -> List[str]:
        """
        模糊匹配初始化函数
        
        查找所有包含 base_name 和初始化后缀的函数
        例如：base_name="curl" -> 匹配 "curl_easy_init", "curl_global_init" 等
        """
        self._ensure_function_cache()
        if not self._all_functions_cache:
            return []
        
        base_lower = base_name.lower()
        matches = []
        
        for func_name in self._all_functions_cache:
            func_lower = func_name.lower()
            
            # 检查是否包含 base_name 和初始化后缀
            if base_lower in func_lower:
                for suffix in INIT_SUFFIXES:
                    if func_lower.endswith(suffix):
                        matches.append(func_name)
                        break
        
        return matches
    
    def _extract_function_name(self, func_sig: str) -> Optional[str]:
        """
        从函数签名中提取简单函数名
        
        例如: "void curl_easy_setopt(CURL *, ...)" -> "curl_easy_setopt"
        """
        import re
        match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*\(', func_sig)
        if match:
            return match.group(1)
        return None
    
    def _extract_call_sequence_from_usage_examples(
        self,
        target_func: str,
        context: Dict
    ) -> Optional[List[str]]:
        """
        从 usage examples 中提取完整的API组合调用序列
        
        改进策略：
        1. 分析每个示例中的完整函数调用顺序（包括配置、使用、清理等）
        2. 识别与目标函数一起使用的所有API（不仅仅是初始化函数）
        3. 找到最常见的API组合模式
        4. 返回包含目标函数及其完整依赖的序列
        
        不再只关注"初始化"和"清理"，而是提取真实使用场景中的完整API组合
        """
        usage_examples = context.get('usage_examples', [])
        if not usage_examples:
            return None
        
        target_func_simple = self._extract_function_name(target_func)
        if not target_func_simple:
            target_func_simple = target_func.split('(')[0].strip()
        
        # 收集所有示例中的完整调用序列
        all_sequences = []
        
        for example in usage_examples:
            source_code = example.get('source', '')
            if not source_code:
                continue
            
            # 提取函数调用序列
            calls = self._extract_function_calls_from_code(source_code)
            if not calls:
                continue
            
            # 找到目标函数的位置
            target_pos = self._find_function_in_calls(calls, target_func_simple)
            if target_pos is None:
                continue
            
            # 提取包含目标函数的完整API序列
            # 包括：目标函数之前的所有API + 目标函数 + 目标函数之后的相关API
            sequence = []
            
            # 目标函数之前的所有API调用（真实使用场景中的组合）
            for i in range(target_pos):
                func_name = self._normalize_function_name(calls[i])
                # 只保留项目中真实存在的API函数
                if self._function_exists(func_name):
                    sequence.append(func_name)
            
            # 目标函数本身
            sequence.append(target_func_simple)
            
            # 目标函数之后的API调用（包括清理、结果查询等）
            # 不再只检查"清理函数"，而是提取所有相关的API调用
            for i in range(target_pos + 1, len(calls)):
                func_name = self._normalize_function_name(calls[i])
                if self._function_exists(func_name):
                    # 检查是否与目标函数相关（有共同前缀或命名空间）
                    # 或者是在真实代码中一起使用的函数
                    if (self._is_related_function(func_name, target_func_simple) or
                        self._is_cleanup_function(func_name) or
                        self._appears_together_in_examples(func_name, target_func_simple, usage_examples)):
                        sequence.append(func_name)
            
            if len(sequence) > 1:  # 至少包含目标函数和一个依赖
                all_sequences.append(sequence)
                logger.debug(f"Extracted complete API sequence from example: {sequence}")
        
        if not all_sequences:
            return None
        
        # 找到最常见的API组合模式
        # 策略：统计每个函数在序列中出现的频率和平均位置
        func_positions = {}  # {func_name: [positions]}
        func_frequencies = {}  # {func_name: count}
        
        for sequence in all_sequences:
            for pos, func in enumerate(sequence):
                if func not in func_positions:
                    func_positions[func] = []
                    func_frequencies[func] = 0
                func_positions[func].append(pos)
                func_frequencies[func] += 1
        
        # 计算每个函数的平均位置（考虑频率权重）
        func_avg_pos = {}
        for func, positions in func_positions.items():
            # 平均位置，但优先考虑出现频率高的函数
            avg_pos = sum(positions) / len(positions)
            # 结合频率和位置：频率高的函数即使位置稍后，也应该优先
            func_avg_pos[func] = (avg_pos, func_frequencies[func])
        
        # 按平均位置排序（主要），频率作为次要排序
        sorted_funcs = sorted(
            func_avg_pos.items(),
            key=lambda x: (x[1][0], -x[1][1])  # 位置优先，频率次之（负号表示降序）
        )
        result = [func for func, _ in sorted_funcs]
        
        # 确保目标函数在序列中
        if target_func_simple not in result:
            result.append(target_func_simple)
        
        if len(result) > 1:
            logger.info(f"✓ Extracted complete API combination sequence ({len(result)} APIs): {result}")
        
        return result if len(result) > 1 else None
    
    def _appears_together_in_examples(
        self,
        func1: str,
        func2: str,
        usage_examples: List[Dict]
    ) -> bool:
        """
        检查两个函数是否在usage examples中经常一起出现
        
        这用于识别真实使用场景中的API组合模式
        """
        together_count = 0
        total_count = 0
        
        for example in usage_examples:
            source_code = example.get('source', '')
            if not source_code:
                continue
            
            calls = self._extract_function_calls_from_code(source_code)
            if not calls:
                continue
            
            normalized_calls = [self._normalize_function_name(c) for c in calls]
            
            has_func1 = func1 in normalized_calls
            has_func2 = func2 in normalized_calls
            
            if has_func1 or has_func2:
                total_count += 1
                if has_func1 and has_func2:
                    together_count += 1
        
        # 如果两个函数在至少50%的示例中一起出现，认为它们是组合使用的
        return total_count > 0 and (together_count / total_count) >= 0.5
    
    def _is_cleanup_function(self, func_name: str) -> bool:
        """判断函数是否是清理函数"""
        func_lower = func_name.lower()
        return any(
            func_lower.endswith(suffix) or suffix in func_lower
            for suffix in CLEANUP_SUFFIXES
        ) and self._function_exists(func_name)
    
    def _is_related_function(self, func_name: str, target_func: str) -> bool:
        """
        判断函数是否与目标函数相关
        
        检查：
        1. 函数名有共同的前缀
        2. 函数存在于项目中
        """
        if not self._function_exists(func_name):
            return False
        
        # 提取共同前缀（例如：curl_easy_setopt 和 curl_easy_perform 都有 curl_easy_ 前缀）
        target_parts = target_func.lower().split('_')
        func_parts = func_name.lower().split('_')
        
        # 检查是否有至少 2 个共同的前缀部分
        common_prefix_len = 0
        for i in range(min(len(target_parts), len(func_parts))):
            if target_parts[i] == func_parts[i]:
                common_prefix_len += 1
            else:
                break
        
        # 如果有至少 2 个共同前缀，认为是相关函数
        return common_prefix_len >= 2
    
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


def format_api_combinations_for_prompt(api_combinations: Dict, target_function: str) -> str:
    """
    将API组合信息格式化为适合注入 prompt 的文本
    
    Args:
        api_combinations: find_api_combinations() 返回的字典
        target_function: 目标函数名
    
    Returns:
        格式化的 Markdown 文本
    """
    if not api_combinations:
        return ""
    
    sections = []
    sections.append("## 🔗 API Composition Analysis\n")
    
    # Check if this is LLM-enhanced analysis
    llm_metadata = api_combinations.get('llm_metadata', {})
    is_llm_enhanced = bool(llm_metadata)
    
    if is_llm_enhanced:
        sections.append("**Source**: LLM-enhanced analysis (high confidence)\n")
        if llm_metadata.get('confidence_note'):
            sections.append(f"**Note**: {llm_metadata['confidence_note']}\n")
    
    # 1. 调用顺序
    if api_combinations.get('call_sequence'):
        sections.append("### ✅ Recommended Call Sequence\n")
        sections.append("**IMPORTANT**: Follow this order to ensure correct API usage:\n")
        for i, func in enumerate(api_combinations['call_sequence'], 1):
            if func == target_function:
                sections.append(f"{i}. **`{func}`** ← TARGET FUNCTION")
            else:
                sections.append(f"{i}. `{func}`")
        sections.append("")
    
    # 2. 前置依赖（初始化）
    if api_combinations.get('prerequisites'):
        sections.append("### ⚠️ Prerequisites (Initialization)\n")
        sections.append("These functions **MUST** be called before the target function:\n")
        for prereq in api_combinations['prerequisites']:
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
    if api_combinations.get('data_dependencies'):
        sections.append("### 📊 Data Flow Dependencies\n")
        for src, dst in api_combinations['data_dependencies']:
            sections.append(f"- `{src}` produces data consumed by `{dst}`")
        sections.append("")
    
    # 7. 初始化代码模板
    if api_combinations.get('initialization_code'):
        sections.append("### 💡 Initialization Code Template\n")
        sections.append("```c")
        sections.extend(api_combinations['initialization_code'])
        sections.append("```\n")
    
    # 8. LLM call pattern example (if available)
    if is_llm_enhanced and llm_metadata.get('has_call_pattern'):
        sections.append("### 📝 Complete Usage Pattern\n")
        sections.append("```c")
        # Extract from initialization_code (which contains the call pattern)
        for line in api_combinations.get('initialization_code', []):
            if line.startswith('//'):
                sections.append(line.replace('// ', ''))
        sections.append("```\n")
    
    return "\n".join(sections)


def get_api_combinations(project_name: str, target_function: str) -> Optional[Dict]:
    """
    便捷函数：获取可以与目标函数组合使用的API
    
    Args:
        project_name: 项目名称（如 "igraph"）
        target_function: 目标函数签名
    
    Returns:
        API组合信息字典，如果查找失败则返回 None
    """
    try:
        analyzer = APICompositionAnalyzer(project_name)
        api_combinations = analyzer.find_api_combinations(target_function)
        return api_combinations if api_combinations['call_sequence'] else None
    except Exception as e:
        logger.error(f"Failed to get API combinations: {e}", exc_info=True)
        return None


if __name__ == "__main__":
    # 测试
    import sys
    logging.basicConfig(level=logging.DEBUG)
    
    if len(sys.argv) < 3:
        print("Usage: python api_composition_analyzer.py <project_name> <function_name>")
        sys.exit(1)
    
    project = sys.argv[1]
    func = sys.argv[2]
    
    # 设置 FuzzIntrospector endpoint
    from data_prep.introspector import set_introspector_endpoints, DEFAULT_INTROSPECTOR_ENDPOINT
    set_introspector_endpoints(DEFAULT_INTROSPECTOR_ENDPOINT)
    
    analyzer = APICompositionAnalyzer(project)
    result = analyzer.find_api_combinations(func)
    
    print("\n" + "="*60)
    print(format_api_combinations_for_prompt(result, func))
    print("="*60)

