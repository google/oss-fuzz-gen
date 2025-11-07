#!/usr/bin/env python3
"""
API Context Extractor - 基于 FuzzIntrospector

从 FuzzIntrospector 提取 API 上下文，用于指导 LLM 生成正确的 fuzzer。

核心功能：
1. 从 FuzzIntrospector 查询函数签名和参数类型
2. 查询相关类型定义
3. 从现有 fuzzer 中提取用法示例
4. 识别需要初始化的类型
5. 生成结构化的 API 上下文

使用方法：
    from agent_graph.api_context_extractor import get_api_context
    
    context = get_api_context(
        project_name="igraph",
        function_signature="igraph_sparsemat_arpack_rssolve"
    )
"""

import logging
import re
from typing import Dict, List, Optional, Set
from data_prep import introspector
from agent_graph.api_heuristics import (
    INIT_SUFFIXES,
    CLEANUP_SUFFIXES,
    INIT_REQUIRED_KEYWORDS,
    clean_type_name,
    is_primitive_type,
    requires_initialization as check_requires_initialization,
    get_base_name_from_type
)

logger = logging.getLogger(__name__)


class APIContextExtractor:
    """从 FuzzIntrospector 提取 API 上下文"""
    
    def __init__(self, project_name: str):
        self.project_name = project_name
        self._all_functions_cache: Optional[Set[str]] = None
    
    def extract(self, function_signature: str) -> Dict:
        """
        提取函数的 API 上下文
        
        Args:
            function_signature: 函数签名（如 "igraph_sparsemat_arpack_rssolve"）
        
        Returns:
            包含以下字段的字典：
            - parameters: 参数列表
            - return_type: 返回类型
            - type_definitions: 类型定义字典
            - usage_examples: 用法示例列表
            - initialization_patterns: 初始化模式列表
            - related_functions: 相关函数列表
        """
        logger.info(f"Extracting API context for {function_signature}")
        
        context = {
            'parameters': [],
            'return_type': '',
            'type_definitions': {},
            'usage_examples': [],
            'initialization_patterns': [],
            'related_functions': [],
            'side_effects': {}  # NEW: 副作用分析
        }
        
        try:
            # 1. 提取函数信息（参数和返回类型）
            self._extract_function_info(function_signature, context)
            
            # 2. 提取类型定义
            self._extract_type_definitions(context)
            
            # 3. 提取用法示例
            self._extract_usage_examples(function_signature, context)
            
            # 4. 识别初始化模式
            self._identify_initialization_patterns(context)
            
            # 5. 查找相关函数
            self._find_related_functions(context)
            
            # 6. 识别副作用 (NEW)
            self._identify_side_effects(function_signature, context)
            
            logger.info(f"Successfully extracted API context for {function_signature}")
            logger.info(f"  - Parameters: {len(context['parameters'])}")
            logger.info(f"  - Type definitions: {len(context['type_definitions'])}")
            logger.info(f"  - Usage examples: {len(context['usage_examples'])}")
            logger.info(f"  - Initialization patterns: {len(context['initialization_patterns'])}")
            logger.info(f"  - Side effects identified: {bool(context['side_effects'])}")
            
        except Exception as e:
            logger.error(f"Failed to extract API context: {e}", exc_info=True)
        
        return context
    
    def _extract_function_info(self, func_sig: str, context: Dict):
        """提取函数签名信息"""
        logger.debug(f"Extracting function info for {func_sig}")
        
        # 方法 1 (NEW): 使用 Debug Types API（更准确）
        try:
            arg_types = introspector.query_introspector_function_debug_arg_types(
                self.project_name, func_sig
            )
            if arg_types:
                # Debug types 返回参数类型列表
                context['parameters'] = [
                    {
                        'name': f'param{i}',
                        'type': arg_type
                    }
                    for i, arg_type in enumerate(arg_types)
                ]
                logger.debug(f"Extracted {len(arg_types)} parameters from debug types")
                
                # 尝试获取返回类型（从函数签名推断）
                context['return_type'] = self._infer_return_type_from_signature(func_sig)
                return
        except Exception as e:
            logger.debug(f"Could not get debug types: {e}")
        
        # 方法 2 (Fallback): 从源码解析
        func_source = introspector.query_introspector_function_source(
            self.project_name, func_sig
        )
        
        if func_source:
            # 从源码中解析函数签名
            parsed = self._parse_function_signature_from_source(func_source)
            if parsed:
                context['parameters'] = parsed.get('parameters', [])
                context['return_type'] = parsed.get('return_type', '')
                logger.debug(f"Parsed {len(context['parameters'])} parameters from source")
                return
        
        # 方法 3: 使用默认值（最后手段）
        logger.warning(f"Could not get function info for {func_sig}, using defaults")
        context['parameters'] = []
        context['return_type'] = 'int'  # 默认
    
    def _infer_return_type_from_signature(self, func_sig: str) -> str:
        """从函数签名推断返回类型"""
        # 简单启发式规则
        if func_sig.startswith('void '):
            return 'void'
        elif func_sig.startswith('int '):
            return 'int'
        elif func_sig.startswith('char '):
            return 'char'
        elif func_sig.startswith('bool '):
            return 'bool'
        elif '*' in func_sig.split('(')[0]:
            return 'pointer'
        else:
            return 'int'  # 默认
    
    def _parse_function_signature_from_source(self, source: str) -> Optional[Dict]:
        """从源码中解析函数签名"""
        # 简单的正则表达式解析
        # 匹配: return_type function_name(params) {
        pattern = r'^\s*([a-zA-Z_][\w\s\*]*?)\s+([a-zA-Z_]\w*)\s*\((.*?)\)\s*\{'
        
        match = re.search(pattern, source, re.MULTILINE | re.DOTALL)
        if not match:
            return None
        
        return_type = match.group(1).strip()
        params_str = match.group(3).strip()
        
        # 解析参数
        parameters = []
        if params_str and params_str != 'void':
            for param in params_str.split(','):
                param = param.strip()
                if not param:
                    continue
                
                # 简单解析: type name
                parts = param.rsplit(None, 1)
                if len(parts) == 2:
                    param_type, param_name = parts
                    parameters.append({
                        'name': param_name,
                        'type': param_type
                    })
                else:
                    # 只有类型，没有名字
                    parameters.append({
                        'name': f'param{len(parameters)}',
                        'type': param
                    })
        
        return {
            'return_type': return_type,
            'parameters': parameters
        }
    
    def _extract_type_definitions(self, context: Dict):
        """提取参数类型的定义"""
        logger.debug("Extracting type definitions")
        
        # 获取项目的所有类型定义（一次性查询）
        try:
            all_types = introspector.query_introspector_type_definition(
                self.project_name
            )
            # 构建类型名到定义的映射
            type_map = {t.get('name', ''): t for t in all_types if t.get('name')}
            logger.debug(f"Loaded {len(type_map)} type definitions")
        except Exception as e:
            logger.debug(f"Could not get type definitions: {e}")
            type_map = {}
        
        # 为每个参数查找类型定义
        for param in context['parameters']:
            param_type = clean_type_name(param['type'])
            
            # 跳过基本类型
            if is_primitive_type(param_type):
                continue
            
            # 查找类型定义
            if param_type in type_map:
                context['type_definitions'][param_type] = type_map[param_type]
                logger.debug(f"Found type definition for {param_type}")
    
    def _extract_usage_examples(self, func_sig: str, context: Dict):
        """从现有代码中提取用法示例（优化采样策略）"""
        logger.debug(f"Extracting usage examples for {func_sig}")
        
        # 方法 0 (HIGHEST PRIORITY): 从测试文件提取用法（最干净的API使用示例）
        try:
            # Extract simple function name from signature for test xref query
            # e.g., "void curl_easy_perform(CURL *)" -> "curl_easy_perform"
            func_name = self._extract_function_name(func_sig)
            if func_name:
                logger.debug(f"Querying test xrefs for function: {func_name}")
                test_xrefs = introspector.query_introspector_for_tests_xref(
                    self.project_name, [func_name]
                )
                
                # test_xrefs format: {'source': [lines], 'details': [structured_snippets]}
                if test_xrefs:
                    # Prefer 'details' if available (structured call information)
                    details = test_xrefs.get('details', [])
                    if details:
                        logger.debug(f"Found {len(details)} detailed test examples")
                        for i, detail_lines in enumerate(details[:3], 1):  # Limit to 3
                            if detail_lines:  # detail_lines is a list of code lines
                                source_code = '\n'.join(detail_lines)
                                context['usage_examples'].append({
                                    'source': source_code,
                                    'file': 'test_file',  # Generic, FI doesn't give specific path
                                    'function': f'test_example_{i}',
                                    'line': 0,
                                    'source_type': 'test_file',  # HIGHEST quality marker
                                    'priority': 1000  # Far higher than other sources
                                })
                        logger.info(f"✓ Added {len(details[:3])} high-quality test examples")
                        return  # Test files are the cleanest examples - use them exclusively
                    
                    # Fallback: use 'source' (plain text snippets)
                    source_lines = test_xrefs.get('source', [])
                    if source_lines:
                        # source_lines is a list of strings, need to group them
                        source_code = '\n'.join(source_lines[:50])  # Limit total lines
                        if source_code.strip():
                            context['usage_examples'].append({
                                'source': source_code,
                                'file': 'test_file',
                                'function': 'test_example',
                                'line': 0,
                                'source_type': 'test_file',
                                'priority': 1000
                            })
                            logger.info(f"✓ Added test file example ({len(source_lines)} lines)")
                            return
        except Exception as e:
            logger.debug(f"Could not get test xrefs: {e}")
        
        # 方法 1 (Fallback): 使用 Sample XRefs API（预处理的高质量示例）
        try:
            sample_xrefs = introspector.query_introspector_sample_xrefs(
                self.project_name, func_sig
            )
            if sample_xrefs:
                logger.debug(f"Found {len(sample_xrefs)} sample cross-references")
                
                # Sample xrefs 已经是预处理的代码片段
                for i, source_code in enumerate(sample_xrefs[:3]):  # 限制3个
                    context['usage_examples'].append({
                        'source': source_code,
                        'file': '',  # Sample xrefs 不包含文件信息
                        'function': f'example_{i+1}',
                        'line': 0,
                        'source_type': 'sample_xref'
                    })
                logger.debug(f"Added {len(context['usage_examples'])} sample xref examples")
                return  # 如果有 sample xrefs，优先使用
        except Exception as e:
            logger.debug(f"Could not get sample xrefs: {e}")
        
        # Note: 方法2 (call_sites) 已移除
        # 理由：
        #  - test_xrefs 和 sample_xrefs 已提供足够高质量的示例
        #  - call_sites 需要二次查询、优先级排序、snippet提取，复杂度高
        #  - 质量不如前两者（包含内部实现、业务逻辑）
        # 特殊用例（如 function_analyzer 的迭代学习）仍可直接调用底层 API
    
    def _identify_initialization_patterns(self, context: Dict):
        """识别需要初始化的类型和初始化方法"""
        logger.debug("Identifying initialization patterns")
        
        for param in context['parameters']:
            param_type = clean_type_name(param['type'])
            param_name = param['name']
            
            # 检查是否需要初始化
            if check_requires_initialization(param_type, param):
                # 推断初始化方法
                init_method = self._infer_initialization_method(param_type)
                
                context['initialization_patterns'].append({
                    'parameter': param_name,
                    'type': param_type,
                    'method': init_method,
                    'reason': self._get_initialization_reason(param_type)
                })
                
                logger.debug(f"Identified initialization pattern for {param_type}")
    
    
    def _infer_initialization_method(self, param_type: str) -> str:
        """推断初始化方法"""
        base_name = get_base_name_from_type(param_type)
        
        # 检查是否存在初始化函数
        for suffix in INIT_SUFFIXES:
            init_func = base_name + suffix
            if self._function_exists(init_func):
                return f"{init_func}(&var)"
        
        # 默认：使用 memset
        return f"memset(&var, 0, sizeof({param_type}))"
    
    def _get_initialization_reason(self, param_type: str) -> str:
        """获取需要初始化的原因"""
        type_lower = param_type.lower()
        
        for kw in INIT_REQUIRED_KEYWORDS:
            if kw in type_lower:
                return f"Type name contains '{kw}', typically requires initialization"
        
        return "Output parameter of struct type"
    
    def _find_related_functions(self, context: Dict):
        """查找相关的初始化/清理函数"""
        logger.debug("Finding related functions")
        
        for param_type in context['type_definitions'].keys():
            base_name = get_base_name_from_type(param_type)
            
            # 查找初始化函数
            for suffix in INIT_SUFFIXES:
                func_name = base_name + suffix
                if self._function_exists(func_name):
                    context['related_functions'].append({
                        'name': func_name,
                        'type': 'initialization',
                        'for_type': param_type
                    })
            
            # 查找清理函数
            for suffix in CLEANUP_SUFFIXES:
                func_name = base_name + suffix
                if self._function_exists(func_name):
                    context['related_functions'].append({
                        'name': func_name,
                        'type': 'cleanup',
                        'for_type': param_type
                    })
    
    def _identify_side_effects(self, func_sig: str, context: Dict):
        """识别函数的副作用
        
        使用两种方法：
        1. 分析函数源代码中的关键词（快速但可能不完整）
        2. 分析函数调用的其他函数（functions_reached）（更准确）
        """
        logger.debug(f"Identifying side effects for {func_sig}")
        
        side_effects = {
            'modifies_global_state': False,
            'performs_io': False,
            'allocates_memory': False,
            'frees_memory': False,
            'has_output_params': False,
            'indicators': []
        }
        
        try:
            # 方法1: 从函数源码推断副作用（原有方法）
            func_source = introspector.query_introspector_function_source(
                self.project_name, func_sig
            )
            
            if func_source:
                source_lower = func_source.lower()
                
                # 检查I/O操作
                io_keywords = ['printf', 'fprintf', 'write', 'read', 'fwrite', 'fread', 
                               'fopen', 'fclose', 'open(', 'close(']
                if any(kw in source_lower for kw in io_keywords):
                    side_effects['performs_io'] = True
                    side_effects['indicators'].append('Contains I/O operations (source)')
                
                # 检查内存分配
                alloc_keywords = ['malloc', 'calloc', 'realloc', 'new ', 'alloc']
                if any(kw in source_lower for kw in alloc_keywords):
                    side_effects['allocates_memory'] = True
                    side_effects['indicators'].append('Allocates memory (source)')
                
                # 检查内存释放
                free_keywords = ['free(', 'delete ', 'release']
                if any(kw in source_lower for kw in free_keywords):
                    side_effects['frees_memory'] = True
                    side_effects['indicators'].append('Frees memory (source)')
                
                # 检查全局变量访问
                if 'static ' in source_lower or 'global' in source_lower:
                    side_effects['modifies_global_state'] = True
                    side_effects['indicators'].append('May modify global state (source)')
            
            # 方法2: 从 functions_reached 推断副作用（新增）
            try:
                functions_reached = introspector.query_introspector_functions_reached(
                    self.project_name, func_sig
                )
                
                if functions_reached:
                    logger.debug(f"Analyzing {len(functions_reached)} functions reached")
                    
                    for called_func in functions_reached:
                        func_lower = called_func.lower()
                        
                        # I/O 函数
                        io_funcs = ['printf', 'fprintf', 'scanf', 'fscanf', 'fopen', 
                                   'fclose', 'fread', 'fwrite', 'write', 'read', 
                                   'open', 'close', 'puts', 'fputs', 'gets', 'fgets']
                        if any(io_func in func_lower for io_func in io_funcs):
                            if not side_effects['performs_io']:
                                side_effects['performs_io'] = True
                                side_effects['indicators'].append(
                                    f'Calls I/O function: {called_func[:50]}'
                                )
                        
                        # 内存管理函数
                        alloc_funcs = ['malloc', 'calloc', 'realloc', 'operator new']
                        if any(alloc_func in func_lower for alloc_func in alloc_funcs):
                            if not side_effects['allocates_memory']:
                                side_effects['allocates_memory'] = True
                                side_effects['indicators'].append(
                                    f'Calls allocation: {called_func[:50]}'
                                )
                        
                        free_funcs = ['free', 'delete', 'operator delete']
                        if any(free_func in func_lower for free_func in free_funcs):
                            if not side_effects['frees_memory']:
                                side_effects['frees_memory'] = True
                                side_effects['indicators'].append(
                                    f'Calls free: {called_func[:50]}'
                                )
            
            except Exception as e:
                logger.debug(f"Could not analyze functions_reached: {e}")
            
            # 从参数推断副作用
            for param in context.get('parameters', []):
                param_type = param.get('type', '')
                # 输出参数（非const指针）
                if '*' in param_type and 'const' not in param_type.lower():
                    side_effects['has_output_params'] = True
                    side_effects['indicators'].append(f'Has output parameter: {param["name"]}')
                    break
            
            context['side_effects'] = side_effects
            logger.debug(f"Identified {len(side_effects['indicators'])} side effect indicators")
            
        except Exception as e:
            logger.debug(f"Could not identify side effects: {e}")
            context['side_effects'] = side_effects
    
    def _extract_function_name(self, func_sig: str) -> Optional[str]:
        """
        从函数签名中提取简单函数名
        
        Examples:
            "void curl_easy_perform(CURL *)" -> "curl_easy_perform"
            "int parse_header(const char*, size_t)" -> "parse_header"
            "igraph_sparsemat_arpack_rssolve" -> "igraph_sparsemat_arpack_rssolve"
        """
        import re
        
        # Case 1: Full signature with parentheses (e.g., "void func(int x)")
        if '(' in func_sig:
            # Extract the last identifier before '('
            match = re.search(r'\b([a-zA-Z_]\w*)\s*\(', func_sig)
            if match:
                return match.group(1)
        
        # Case 2: Simple function name without signature
        # Clean up any leading type info (e.g., "void func" -> "func")
        parts = func_sig.strip().split()
        if parts:
            return parts[-1]  # Last word is likely the function name
        
        return None
    
    def _function_exists(self, func_name: str) -> bool:
        """检查函数是否存在"""
        # 懒加载：第一次调用时获取所有函数列表
        if self._all_functions_cache is None:
            try:
                # 查询项目的所有函数
                all_funcs = introspector.query_introspector_all_functions(
                    self.project_name
                )
                self._all_functions_cache = set(
                    f.get('function-name', '') for f in all_funcs
                )
                logger.debug(f"Cached {len(self._all_functions_cache)} function names")
            except Exception as e:
                logger.debug(f"Could not get all functions: {e}")
                self._all_functions_cache = set()
        
        return func_name in self._all_functions_cache


def get_api_context(project_name: str, function_signature: str) -> Optional[Dict]:
    """
    便捷函数：获取函数的 API 上下文
    
    Args:
        project_name: 项目名称（如 "igraph"）
        function_signature: 函数签名（如 "igraph_sparsemat_arpack_rssolve"）
    
    Returns:
        API 上下文字典，如果提取失败则返回 None
    """
    try:
        extractor = APIContextExtractor(project_name)
        context = extractor.extract(function_signature)
        return context if context['parameters'] or context['usage_examples'] else None
    except Exception as e:
        logger.error(f"Failed to get API context: {e}", exc_info=True)
        return None


def format_api_context_for_prompt(context: Dict) -> str:
    """
    将 API 上下文格式化为适合注入 prompt 的文本（优化版）
    
    Args:
        context: API 上下文字典
    
    Returns:
        格式化的文本
    """
    if not context:
        return ""
    
    sections = []
    
    # 1. 参数信息
    if context.get('parameters'):
        sections.append("### Parameters\n")
        for param in context['parameters']:
            sections.append(f"- `{param['name']}` ({param['type']})")
        sections.append("")
    
    # 2. 副作用信息（NEW - 重要！）
    if context.get('side_effects') and context['side_effects'].get('indicators'):
        sections.append("### ⚠️ Side Effects & Behavior\n")
        side_effects = context['side_effects']
        for indicator in side_effects['indicators']:
            sections.append(f"- {indicator}")
        sections.append("")
    
    # 3. 初始化要求（重要！）
    if context.get('initialization_patterns'):
        sections.append("### ⚠️ Initialization Requirements\n")
        for pattern in context['initialization_patterns']:
            sections.append(
                f"- **{pattern['parameter']}** ({pattern['type']}): "
                f"{pattern['method']}"
            )
            sections.append(f"  Reason: {pattern['reason']}")
        sections.append("")
    
    # 4. 相关函数
    if context.get('related_functions'):
        init_funcs = [f for f in context['related_functions'] if f['type'] == 'initialization']
        cleanup_funcs = [f for f in context['related_functions'] if f['type'] == 'cleanup']
        
        if init_funcs:
            sections.append("### Related Initialization Functions\n")
            for func in init_funcs:
                sections.append(f"- `{func['name']}` for `{func['for_type']}`")
            sections.append("")
        
        if cleanup_funcs:
            sections.append("### Related Cleanup Functions\n")
            for func in cleanup_funcs:
                sections.append(f"- `{func['name']}` for `{func['for_type']}`")
            sections.append("")
    
    # 5. 用法示例（优化：优先显示测试文件，明确标注质量）
    if context.get('usage_examples'):
        sections.append("### Usage Examples from Existing Code\n")
        for i, example in enumerate(context['usage_examples'][:2], 1):
            source_type = example.get('source_type', 'unknown')
            
            # Quality indicators (from highest to lowest)
            if source_type == 'test_file':
                quality_indicator = "🏆 TEST FILE (Highest Quality - Clean API Usage)"
            elif source_type == 'sample_xref':
                quality_indicator = "✓ High-quality"
            else:
                quality_indicator = ""
            
            sections.append(f"#### Example {i}: {example['function']} {quality_indicator}")
            if example.get('file'):
                sections.append(f"Source: {example['file']}")
            sections.append(f"```c\n{example['source']}\n```\n")
    
    if sections:
        return "## API Context\n\n" + "\n".join(sections)
    
    return ""

