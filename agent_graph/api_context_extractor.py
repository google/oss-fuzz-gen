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

logger = logging.getLogger(__name__)


class APIContextExtractor:
    """从 FuzzIntrospector 提取 API 上下文"""
    
    # 需要初始化的类型关键词
    INIT_REQUIRED_KEYWORDS = [
        'storage', 'context', 'state', 'buffer', 
        'data', 'cache', 'pool', 'arena'
    ]
    
    # 初始化函数后缀
    INIT_SUFFIXES = ['_init', '_create', '_new', '_alloc', '_setup']
    
    # 清理函数后缀
    CLEANUP_SUFFIXES = ['_destroy', '_free', '_delete', '_cleanup', '_close', '_release']
    
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
            'related_functions': []
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
            
            logger.info(f"Successfully extracted API context for {function_signature}")
            logger.info(f"  - Parameters: {len(context['parameters'])}")
            logger.info(f"  - Type definitions: {len(context['type_definitions'])}")
            logger.info(f"  - Usage examples: {len(context['usage_examples'])}")
            logger.info(f"  - Initialization patterns: {len(context['initialization_patterns'])}")
            
        except Exception as e:
            logger.error(f"Failed to extract API context: {e}", exc_info=True)
        
        return context
    
    def _extract_function_info(self, func_sig: str, context: Dict):
        """提取函数签名信息"""
        logger.debug(f"Extracting function info for {func_sig}")
        
        # 方法 1: 尝试从 FuzzIntrospector 获取函数签名
        # 注意：FuzzIntrospector 可能没有直接的 "get function signature" API
        # 我们需要从函数源码中解析
        
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
        
        # 方法 2: 从函数名推断（fallback）
        logger.warning(f"Could not get function source for {func_sig}, using fallback")
        context['parameters'] = []
        context['return_type'] = 'int'  # 默认
    
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
            param_type = self._clean_type(param['type'])
            
            # 跳过基本类型
            if self._is_primitive_type(param_type):
                continue
            
            # 查找类型定义
            if param_type in type_map:
                context['type_definitions'][param_type] = type_map[param_type]
                logger.debug(f"Found type definition for {param_type}")
    
    def _extract_usage_examples(self, func_sig: str, context: Dict):
        """从现有代码中提取用法示例"""
        logger.debug(f"Extracting usage examples for {func_sig}")
        
        try:
            # 查询调用点
            call_sites = introspector.query_introspector_call_sites_metadata(
                self.project_name, func_sig
            )
            
            logger.debug(f"Found {len(call_sites)} call sites")
            
            # 限制数量，避免过多
            for call_site in call_sites[:3]:
                try:
                    caller_func = call_site.get('src_func', '')
                    if not caller_func:
                        continue
                    
                    # 获取调用者的源码
                    caller_source = introspector.query_introspector_function_source(
                        self.project_name, caller_func
                    )
                    
                    if caller_source:
                        # 提取相关代码片段（包含目标函数调用的部分）
                        snippet = self._extract_relevant_snippet(
                            caller_source, 
                            func_sig
                        )
                        
                        context['usage_examples'].append({
                            'source': snippet or caller_source[:1000],  # 限制长度
                            'file': call_site.get('src_file', ''),
                            'function': caller_func,
                            'line': call_site.get('src_line', 0)
                        })
                        
                        logger.debug(f"Added usage example from {caller_func}")
                except Exception as e:
                    logger.debug(f"Could not extract usage example: {e}")
        
        except Exception as e:
            logger.debug(f"Could not query call sites: {e}")
    
    def _extract_relevant_snippet(self, source: str, func_name: str) -> Optional[str]:
        """提取包含函数调用的相关代码片段"""
        lines = source.split('\n')
        
        # 查找函数调用的行
        for i, line in enumerate(lines):
            if func_name in line:
                # 提取前后各 5 行
                start = max(0, i - 5)
                end = min(len(lines), i + 6)
                return '\n'.join(lines[start:end])
        
        return None
    
    def _identify_initialization_patterns(self, context: Dict):
        """识别需要初始化的类型和初始化方法"""
        logger.debug("Identifying initialization patterns")
        
        for param in context['parameters']:
            param_type = self._clean_type(param['type'])
            param_name = param['name']
            
            # 检查是否需要初始化
            if self._requires_initialization(param_type, param):
                # 推断初始化方法
                init_method = self._infer_initialization_method(param_type)
                
                context['initialization_patterns'].append({
                    'parameter': param_name,
                    'type': param_type,
                    'method': init_method,
                    'reason': self._get_initialization_reason(param_type)
                })
                
                logger.debug(f"Identified initialization pattern for {param_type}")
    
    def _requires_initialization(self, param_type: str, param: Dict) -> bool:
        """判断参数是否需要初始化"""
        # 规则 1: 类型名包含特定关键词
        type_lower = param_type.lower()
        if any(kw in type_lower for kw in self.INIT_REQUIRED_KEYWORDS):
            return True
        
        # 规则 2: 是输出参数（指针类型）且不是 const
        if '*' in param['type'] and 'const' not in param['type']:
            # 进一步检查：如果是结构体类型
            if not self._is_primitive_type(param_type):
                return True
        
        return False
    
    def _infer_initialization_method(self, param_type: str) -> str:
        """推断初始化方法"""
        base_name = param_type.replace('_t', '').replace('struct ', '')
        
        # 检查是否存在初始化函数
        for suffix in self.INIT_SUFFIXES:
            init_func = base_name + suffix
            if self._function_exists(init_func):
                return f"{init_func}(&var)"
        
        # 默认：使用 memset
        return f"memset(&var, 0, sizeof({param_type}))"
    
    def _get_initialization_reason(self, param_type: str) -> str:
        """获取需要初始化的原因"""
        type_lower = param_type.lower()
        
        for kw in self.INIT_REQUIRED_KEYWORDS:
            if kw in type_lower:
                return f"Type name contains '{kw}', typically requires initialization"
        
        return "Output parameter of struct type"
    
    def _find_related_functions(self, context: Dict):
        """查找相关的初始化/清理函数"""
        logger.debug("Finding related functions")
        
        for param_type in context['type_definitions'].keys():
            base_name = param_type.replace('_t', '').replace('struct ', '')
            
            # 查找初始化函数
            for suffix in self.INIT_SUFFIXES:
                func_name = base_name + suffix
                if self._function_exists(func_name):
                    context['related_functions'].append({
                        'name': func_name,
                        'type': 'initialization',
                        'for_type': param_type
                    })
            
            # 查找清理函数
            for suffix in self.CLEANUP_SUFFIXES:
                func_name = base_name + suffix
                if self._function_exists(func_name):
                    context['related_functions'].append({
                        'name': func_name,
                        'type': 'cleanup',
                        'for_type': param_type
                    })
    
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
    
    @staticmethod
    def _clean_type(type_str: str) -> str:
        """清理类型字符串（去掉指针、const 等）"""
        cleaned = type_str.replace('const', '').replace('*', '').replace('&', '').strip()
        # 去掉 struct/enum 前缀
        cleaned = re.sub(r'^(struct|enum|union)\s+', '', cleaned)
        return cleaned
    
    @staticmethod
    def _is_primitive_type(type_name: str) -> bool:
        """判断是否是基本类型"""
        primitives = {
            'int', 'char', 'short', 'long', 'float', 'double', 
            'void', 'bool', 'size_t', 'uint8_t', 'uint16_t', 
            'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 
            'int32_t', 'int64_t'
        }
        return type_name in primitives


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
    将 API 上下文格式化为适合注入 prompt 的文本
    
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
    
    # 2. 初始化要求（重要！）
    if context.get('initialization_patterns'):
        sections.append("### ⚠️ Initialization Requirements\n")
        for pattern in context['initialization_patterns']:
            sections.append(
                f"- **{pattern['parameter']}** ({pattern['type']}): "
                f"{pattern['method']}"
            )
            sections.append(f"  Reason: {pattern['reason']}")
        sections.append("")
    
    # 3. 相关函数
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
    
    # 4. 用法示例
    if context.get('usage_examples'):
        sections.append("### Usage Examples from Existing Code\n")
        for i, example in enumerate(context['usage_examples'][:2], 1):
            sections.append(f"#### Example {i}: {example['function']}")
            if example.get('file'):
                sections.append(f"Source: {example['file']}")
            sections.append(f"```c\n{example['source']}\n```\n")
    
    if sections:
        return "## API Context\n\n" + "\n".join(sections)
    
    return ""

