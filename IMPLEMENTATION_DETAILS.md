# LogicFuzz 架构优化 - 实现细节

## 一、目录结构设计

```
agent_graph/
├── scenario_modeling/          # 新增：场景建模模块
│   ├── __init__.py
│   ├── scenario.py             # APIScenario 类定义
│   ├── scenario_extractor.py   # 场景提取器
│   ├── scenario_analyzer.py    # 场景分析器
│   ├── scenario_db.py          # 场景数据库
│   └── scenario_selector.py    # 场景选择器
│
├── contract_system/            # 新增：契约系统模块
│   ├── __init__.py
│   ├── contract.py             # APIContract 类定义
│   ├── contract_extractor.py   # 契约提取器
│   ├── contract_validator.py   # 契约验证器
│   ├── contract_db.py          # 契约数据库
│   └── contract_injector.py    # 契约检查代码注入器
│
├── coverage_exploration/       # 新增：覆盖率驱动探索模块
│   ├── __init__.py
│   ├── coverage_analyzer.py    # 覆盖率分析器（增强版）
│   ├── gap_detector.py         # 覆盖缺口检测器
│   ├── scenario_explorer.py    # 场景探索器
│   └── variation_generator.py  # 场景变体生成器
│
├── validation/                 # 新增：验证模块
│   ├── __init__.py
│   ├── pre_execution_validator.py  # 执行前验证器
│   ├── static_analyzer.py      # 静态分析器
│   └── runtime_checker.py      # 运行时检查器
│
└── ... (现有模块)
```

## 二、核心类设计

### 2.1 APIScenario (场景模型)

```python
# agent_graph/scenario_modeling/scenario.py

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum

class ScenarioType(Enum):
    USAGE_EXAMPLE = "usage_example"
    DOCUMENTATION = "documentation"
    TEST_CASE = "test_case"
    INFERRED = "inferred"
    VARIATION = "variation"

@dataclass
class APICall:
    """单个 API 调用"""
    function: str
    parameters: Dict[str, any] = field(default_factory=dict)
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    state_before: Dict = field(default_factory=dict)
    state_after: Dict = field(default_factory=dict)
    line_number: Optional[int] = None  # 在原始代码中的行号

@dataclass
class APIScenario:
    """API 场景模型"""
    
    # 场景标识
    scenario_id: str
    scenario_name: str
    scenario_type: ScenarioType
    target_function: str  # 目标函数
    
    # API 序列
    api_sequence: List[APICall] = field(default_factory=list)
    
    # 场景元数据
    context: Dict = field(default_factory=dict)  # 场景上下文
    confidence: float = 0.0  # 0.0-1.0
    frequency: int = 0  # 在真实代码中出现的频率
    source: str = ""  # 来源（文件路径、URL等）
    
    # 覆盖率信息
    coverage_info: Dict = field(default_factory=dict)
    # {
    #   'api_coverage': Set[str],  # 覆盖的 API
    #   'path_coverage': Set[str], # 覆盖的代码路径
    #   'state_coverage': Set[str], # 覆盖的状态
    # }
    
    # 统计信息
    success_rate: float = 0.0  # 成功率
    crash_rate: float = 0.0    # 崩溃率
    false_positive_rate: float = 0.0  # 假阳性率
    execution_count: int = 0  # 执行次数
    
    # 优先级（用于场景选择）
    priority: float = 0.0  # 计算得出
    
    def calculate_priority(self, coverage_gaps: Set[str]) -> float:
        """计算场景优先级"""
        # 优先级 = f(覆盖率缺口, 频率, 成功率, 置信度)
        gap_score = len(self.coverage_info.get('api_coverage', set()) & coverage_gaps)
        freq_score = min(self.frequency / 100.0, 1.0)  # 归一化
        success_score = self.success_rate
        conf_score = self.confidence
        
        # 加权平均
        priority = (
            0.4 * gap_score +      # 覆盖缺口权重最高
            0.2 * freq_score +
            0.2 * success_score +
            0.2 * conf_score
        )
        self.priority = priority
        return priority
    
    def to_dict(self) -> Dict:
        """序列化"""
        return {
            'scenario_id': self.scenario_id,
            'scenario_name': self.scenario_name,
            'scenario_type': self.scenario_type.value,
            'target_function': self.target_function,
            'api_sequence': [
                {
                    'function': call.function,
                    'parameters': call.parameters,
                    'preconditions': call.preconditions,
                    'postconditions': call.postconditions,
                }
                for call in self.api_sequence
            ],
            'context': self.context,
            'confidence': self.confidence,
            'frequency': self.frequency,
            'coverage_info': {
                'api_coverage': list(self.coverage_info.get('api_coverage', set())),
                'path_coverage': list(self.coverage_info.get('path_coverage', set())),
            },
            'success_rate': self.success_rate,
            'crash_rate': self.crash_rate,
            'false_positive_rate': self.false_positive_rate,
            'priority': self.priority,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'APIScenario':
        """反序列化"""
        scenario = cls(
            scenario_id=data['scenario_id'],
            scenario_name=data['scenario_name'],
            scenario_type=ScenarioType(data['scenario_type']),
            target_function=data['target_function'],
            context=data.get('context', {}),
            confidence=data.get('confidence', 0.0),
            frequency=data.get('frequency', 0),
            coverage_info={
                'api_coverage': set(data.get('coverage_info', {}).get('api_coverage', [])),
                'path_coverage': set(data.get('coverage_info', {}).get('path_coverage', [])),
            },
            success_rate=data.get('success_rate', 0.0),
            crash_rate=data.get('crash_rate', 0.0),
            false_positive_rate=data.get('false_positive_rate', 0.0),
            priority=data.get('priority', 0.0),
        )
        
        # 重建 API 序列
        for call_data in data.get('api_sequence', []):
            scenario.api_sequence.append(APICall(
                function=call_data['function'],
                parameters=call_data.get('parameters', {}),
                preconditions=call_data.get('preconditions', []),
                postconditions=call_data.get('postconditions', []),
            ))
        
        return scenario
```

### 2.2 APIContract (契约模型)

```python
# agent_graph/contract_system/contract.py

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum

class PreconditionType(Enum):
    NOT_NULL = "not_null"
    VALID_RANGE = "valid_range"
    INITIALIZED = "initialized"
    STATE_CHECK = "state_check"
    TYPE_CHECK = "type_check"

class PostconditionType(Enum):
    RETURN_NOT_NULL = "return_not_null"
    STATE_CHANGED = "state_changed"
    RESOURCE_ALLOCATED = "resource_allocated"
    RESOURCE_FREED = "resource_freed"

@dataclass
class Precondition:
    """前置条件"""
    type: PreconditionType
    parameter: Optional[str] = None  # 参数名
    condition: str = ""  # 条件表达式（如 "ctx != NULL"）
    error_if_violated: str = ""  # 违反时的错误信息
    check_code: Optional[str] = None  # 检查代码（用于注入）

@dataclass
class Postcondition:
    """后置条件"""
    type: PostconditionType
    guarantee: str = ""  # 保证的内容
    check_code: Optional[str] = None  # 检查代码

@dataclass
class StateTransition:
    """状态转换"""
    from_state: str
    to_state: str
    condition: Optional[str] = None  # 转换条件

@dataclass
class ResourceManagement:
    """资源管理"""
    allocates: List[str] = field(default_factory=list)  # 分配的资源
    requires: List[str] = field(default_factory=list)   # 需要的资源
    cleanup: List[str] = field(default_factory=list)    # 清理函数

@dataclass
class ParameterConstraint:
    """参数约束"""
    parameter_name: str
    type: str
    valid_range: Optional[Tuple[Any, Any]] = None
    required: bool = True
    default_value: Optional[Any] = None
    constraints: List[str] = field(default_factory=list)  # 其他约束

@dataclass
class APIContract:
    """API 调用契约"""
    
    function_name: str
    
    # 前置条件
    preconditions: List[Precondition] = field(default_factory=list)
    
    # 后置条件
    postconditions: List[Postcondition] = field(default_factory=list)
    
    # 状态转换
    state_transitions: List[StateTransition] = field(default_factory=list)
    
    # 资源管理
    resource_management: ResourceManagement = field(default_factory=ResourceManagement)
    
    # 参数约束
    parameter_constraints: Dict[str, ParameterConstraint] = field(default_factory=dict)
    
    # 元数据
    source: str = ""  # 来源（SRS、文档、静态分析等）
    confidence: float = 0.0  # 置信度
    
    def validate_sequence(self, api_sequence: List[str]) -> Tuple[bool, List[str]]:
        """
        验证 API 序列是否符合契约
        
        Returns:
            (is_valid, violations)
        """
        violations = []
        
        # 检查资源管理（init → use → cleanup）
        if self.resource_management.requires:
            # 检查是否有对应的 init 函数
            has_init = any(
                any(req in api for api in api_sequence)
                for req in self.resource_management.requires
            )
            if not has_init:
                violations.append(f"Missing initialization for required resources: {self.resource_management.requires}")
        
        # 检查状态转换
        # TODO: 实现状态转换验证
        
        return len(violations) == 0, violations
    
    def generate_check_code(self) -> str:
        """生成契约检查代码"""
        checks = []
        
        # 生成前置条件检查
        for precond in self.preconditions:
            if precond.check_code:
                checks.append(f"  // Precondition: {precond.condition}")
                checks.append(f"  {precond.check_code}")
                checks.append(f"  if (!({precond.condition})) {{")
                checks.append(f'    // Violation: {precond.error_if_violated}')
                checks.append(f"    return 0;")
                checks.append(f"  }}")
        
        # 生成后置条件检查
        for postcond in self.postconditions:
            if postcond.check_code:
                checks.append(f"  // Postcondition: {postcond.guarantee}")
                checks.append(f"  {postcond.check_code}")
        
        return "\n".join(checks)
```

### 2.3 ScenarioExtractor (场景提取器)

```python
# agent_graph/scenario_modeling/scenario_extractor.py

import logging
from typing import List, Dict, Set
from data_prep import introspector
from agent_graph.scenario_modeling.scenario import APIScenario, APICall, ScenarioType

logger = logging.getLogger(__name__)

class ScenarioExtractor:
    """场景提取器 - 从多源数据提取 API 场景"""
    
    def __init__(self, project_name: str):
        self.project_name = project_name
    
    def extract_from_usage_examples(self, target_function: str) -> List[APIScenario]:
        """从 usage examples 提取场景"""
        from agent_graph.api_context_extractor import APIContextExtractor
        
        extractor = APIContextExtractor(self.project_name)
        context = extractor.extract(target_function)
        
        if not context:
            return []
        
        scenarios = []
        usage_examples = context.get('usage_examples', [])
        
        for idx, example in enumerate(usage_examples):
            source_code = example.get('source', '')
            if not source_code:
                continue
            
            # 提取 API 调用序列
            api_calls = self._extract_api_calls_from_code(source_code, target_function)
            if not api_calls:
                continue
            
            # 创建场景
            scenario = APIScenario(
                scenario_id=f"usage_example_{target_function}_{idx}",
                scenario_name=f"Usage Example {idx+1}",
                scenario_type=ScenarioType.USAGE_EXAMPLE,
                target_function=target_function,
                api_sequence=api_calls,
                source=example.get('file', ''),
                confidence=0.8,  # usage examples 置信度较高
                frequency=1,
            )
            
            scenarios.append(scenario)
        
        logger.info(f"Extracted {len(scenarios)} scenarios from usage examples for {target_function}")
        return scenarios
    
    def extract_from_documentation(self, target_function: str) -> List[APIScenario]:
        """从文档提取场景"""
        # TODO: 实现文档解析
        # 可以从 API 文档、README、示例代码中提取
        return []
    
    def extract_from_test_cases(self, target_function: str) -> List[APIScenario]:
        """从测试用例提取场景"""
        # TODO: 实现测试用例解析
        # 可以从项目的测试文件中提取
        return []
    
    def _extract_api_calls_from_code(self, code: str, target_function: str) -> List[APICall]:
        """从代码中提取 API 调用序列"""
        import re
        
        # 提取函数调用
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*\('
        matches = re.finditer(pattern, code)
        
        api_calls = []
        target_found = False
        
        for match in matches:
            func_name = match.group(1)
            
            # 找到目标函数
            if func_name == target_function or target_function in func_name:
                target_found = True
            
            # 提取目标函数及其前后的 API 调用
            if target_found or func_name in self._get_project_functions():
                api_call = APICall(
                    function=func_name,
                    line_number=code[:match.start()].count('\n') + 1
                )
                api_calls.append(api_call)
        
        return api_calls
    
    def _get_project_functions(self) -> Set[str]:
        """获取项目中的所有函数（缓存）"""
        if not hasattr(self, '_function_cache'):
            try:
                all_funcs = introspector.query_introspector_all_functions(self.project_name)
                self._function_cache = {
                    f.get('function-name', '') or f.get('function_signature', '').split('(')[0]
                    for f in all_funcs
                }
            except Exception as e:
                logger.warning(f"Failed to load function cache: {e}")
                self._function_cache = set()
        
        return self._function_cache
```

### 2.4 ContractExtractor (契约提取器)

```python
# agent_graph/contract_system/contract_extractor.py

import logging
from typing import Dict, List, Optional
from agent_graph.contract_system.contract import (
    APIContract, Precondition, Postcondition, PreconditionType, 
    PostconditionType, ResourceManagement, ParameterConstraint
)

logger = logging.getLogger(__name__)

class ContractExtractor:
    """契约提取器 - 从多源数据提取 API 契约"""
    
    def __init__(self, project_name: str):
        self.project_name = project_name
    
    def extract_from_srs(self, function_analysis: Dict) -> Optional[APIContract]:
        """从 SRS 数据提取契约"""
        srs_data = function_analysis.get('srs_data')
        if not srs_data:
            return None
        
        function_signature = function_analysis.get('function_signature', '')
        function_name = function_signature.split('(')[0] if '(' in function_signature else function_signature
        
        contract = APIContract(
            function_name=function_name,
            source='srs',
            confidence=0.9,  # SRS 数据置信度很高
        )
        
        # 提取前置条件
        preconditions = srs_data.get('preconditions', [])
        for pre in preconditions:
            contract.preconditions.append(Precondition(
                type=PreconditionType.STATE_CHECK,
                condition=pre.get('requirement', ''),
                error_if_violated=pre.get('violation_consequence', ''),
            ))
        
        # 提取后置条件
        postconditions = srs_data.get('postconditions', [])
        for post in postconditions:
            contract.postconditions.append(Postcondition(
                type=PostconditionType.STATE_CHANGED,
                guarantee=post.get('requirement', ''),
            ))
        
        # 提取参数约束
        param_strategies = srs_data.get('parameter_strategies', [])
        for param in param_strategies:
            param_name = param.get('parameter', '')
            if param_name:
                contract.parameter_constraints[param_name] = ParameterConstraint(
                    parameter_name=param_name,
                    type=param.get('type', ''),
                    constraints=param.get('constraints', []),
                )
        
        # 提取资源管理信息
        # 从 constraints 中提取资源管理信息
        constraints = srs_data.get('constraints', [])
        for con in constraints:
            if 'resource' in con.get('type', '').lower():
                # 提取资源管理信息
                impl = con.get('implementation', {})
                sequence = impl.get('sequence', [])
                for step in sequence:
                    code = step.get('code', '')
                    if 'init' in code.lower() or 'create' in code.lower():
                        # 提取 init 函数
                        import re
                        match = re.search(r'(\w+_(?:init|create))', code)
                        if match:
                            contract.resource_management.requires.append(match.group(1))
                    elif 'free' in code.lower() or 'destroy' in code.lower():
                        # 提取 cleanup 函数
                        match = re.search(r'(\w+_(?:free|destroy|cleanup))', code)
                        if match:
                            contract.resource_management.cleanup.append(match.group(1))
        
        return contract
    
    def extract_from_static_analysis(self, function_signature: str, source_code: str) -> Optional[APIContract]:
        """从静态分析提取契约"""
        # TODO: 实现静态分析
        # 可以分析参数类型、返回值类型、可能的 NULL 检查等
        return None
    
    def extract_from_llm(self, function_signature: str, llm) -> Optional[APIContract]:
        """使用 LLM 提取契约"""
        # TODO: 实现 LLM 提取
        return None
```

### 2.5 PreExecutionValidator (执行前验证器)

```python
# agent_graph/validation/pre_execution_validator.py

import logging
from typing import Tuple, List, Dict
from agent_graph.scenario_modeling.scenario import APIScenario
from agent_graph.contract_system.contract import APIContract

logger = logging.getLogger(__name__)

class PreExecutionValidator:
    """执行前验证器 - 在运行前验证代码正确性"""
    
    def __init__(self):
        pass
    
    def validate_scenario(self, scenario: APIScenario, contracts: Dict[str, APIContract]) -> Tuple[bool, List[str]]:
        """
        验证场景是否符合契约
        
        Args:
            scenario: API 场景
            contracts: 函数名 -> 契约的映射
        
        Returns:
            (is_valid, violations)
        """
        violations = []
        
        # 提取场景中的 API 序列
        api_sequence = [call.function for call in scenario.api_sequence]
        
        # 验证每个 API 调用
        for call in scenario.api_sequence:
            func_name = call.function
            contract = contracts.get(func_name)
            
            if not contract:
                continue  # 没有契约，跳过
            
            # 验证前置条件
            # 检查前置条件是否在之前的调用中满足
            pre_violations = self._check_preconditions(call, contract, scenario.api_sequence)
            violations.extend(pre_violations)
            
            # 验证资源管理
            res_violations = self._check_resource_management(call, contract, api_sequence)
            violations.extend(res_violations)
        
        # 验证整体序列
        seq_violations = self._check_sequence_validity(scenario, contracts)
        violations.extend(seq_violations)
        
        is_valid = len(violations) == 0
        if not is_valid:
            logger.warning(f"Scenario {scenario.scenario_id} validation failed: {violations}")
        
        return is_valid, violations
    
    def _check_preconditions(self, call: 'APICall', contract: APIContract, 
                            sequence: List['APICall']) -> List[str]:
        """检查前置条件是否满足"""
        violations = []
        
        for precond in contract.preconditions:
            if precond.type == PreconditionType.NOT_NULL:
                # 检查参数是否为 NULL
                param = precond.parameter
                if param:
                    # 检查之前的调用是否初始化了这个参数
                    # TODO: 实现更复杂的检查逻辑
                    pass
        
        return violations
    
    def _check_resource_management(self, call: 'APICall', contract: APIContract,
                                  api_sequence: List[str]) -> List[str]:
        """检查资源管理是否正确"""
        violations = []
        
        # 检查是否需要资源初始化
        if contract.resource_management.requires:
            for req in contract.resource_management.requires:
                # 检查序列中是否有对应的 init 函数
                if req not in api_sequence:
                    violations.append(
                        f"Missing initialization for {call.function}: {req} not found in sequence"
                    )
        
        # 检查是否有对应的 cleanup
        if contract.resource_management.cleanup:
            # 检查序列末尾是否有 cleanup
            # TODO: 实现更复杂的检查逻辑
            pass
        
        return violations
    
    def _check_sequence_validity(self, scenario: APIScenario, 
                                contracts: Dict[str, APIContract]) -> List[str]:
        """检查序列整体有效性"""
        violations = []
        
        # 检查是否有目标函数
        target_func = scenario.target_function
        has_target = any(call.function == target_func for call in scenario.api_sequence)
        if not has_target:
            violations.append(f"Target function {target_func} not found in sequence")
        
        # 检查 API 调用顺序（基于依赖关系）
        # TODO: 实现拓扑排序检查
        
        return violations
    
    def inject_contract_checks(self, code: str, contracts: Dict[str, APIContract]) -> str:
        """注入契约检查代码"""
        # TODO: 实现代码注入
        # 在 API 调用前后注入检查代码
        return code
```

## 三、集成到现有工作流

### 3.1 修改 Prototyper

```python
# agent_graph/agents/prototyper.py (修改)

class LangGraphPrototyper(LangGraphAgent):
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        # ... 现有代码 ...
        
        # 新增：场景选择
        from agent_graph.scenario_modeling.scenario_selector import ScenarioSelector
        from agent_graph.contract_system.contract_validator import ContractValidator
        from agent_graph.validation.pre_execution_validator import PreExecutionValidator
        
        # 1. 选择场景
        selector = ScenarioSelector(state.get('project_name'))
        scenario = selector.select_scenario(
            target_function=benchmark.get('function_signature'),
            coverage_info=state.get('coverage_info', {}),
            existing_scenarios=state.get('used_scenarios', [])
        )
        
        # 2. 验证场景契约
        contracts = state.get('api_contracts', {})
        validator = PreExecutionValidator()
        is_valid, violations = validator.validate_scenario(scenario, contracts)
        
        if not is_valid:
            # 尝试修复或选择其他场景
            logger.warning(f"Scenario validation failed: {violations}")
            # TODO: 实现修复逻辑
        
        # 3. 基于场景生成代码
        skeleton_code = self._retrieve_skeleton(function_analysis)
        
        # 将场景信息注入 prompt
        scenario_context = self._format_scenario_context(scenario)
        base_prompt = prompt_manager.build_user_prompt(
            "prototyper",
            # ... 现有参数 ...
            scenario_context=scenario_context,  # 新增
        )
        
        # ... 后续代码 ...
```

### 3.2 修改 Supervisor

```python
# agent_graph/nodes/supervisor_node.py (修改)

def _determine_next_action(state: FuzzingWorkflowState) -> str:
    # ... 现有代码 ...
    
    # 新增：覆盖率驱动的场景探索
    if workflow_phase == "optimization":
        coverage_info = state.get('coverage_info', {})
        
        # 检查是否需要探索新场景
        from agent_graph.coverage_exploration.scenario_explorer import ScenarioExplorer
        explorer = ScenarioExplorer(state.get('project_name'))
        
        if explorer.should_explore(coverage_info):
            # 探索新场景
            new_scenarios = explorer.explore(
                target_function=state.get('function_signature'),
                coverage_info=coverage_info
            )
            
            if new_scenarios:
                # 更新场景数据库
                state['new_scenarios'] = new_scenarios
                return "prototyper"  # 重新生成代码
    
    # ... 现有代码 ...
```

## 四、数据库设计

### 4.1 ScenarioDB

```python
# agent_graph/scenario_modeling/scenario_db.py

import json
import os
from typing import List, Dict, Optional
from agent_graph.scenario_modeling.scenario import APIScenario

class ScenarioDB:
    """场景数据库"""
    
    def __init__(self, project_name: str, db_path: str = None):
        self.project_name = project_name
        self.db_path = db_path or f"data/scenarios/{project_name}.json"
        self.scenarios: Dict[str, APIScenario] = {}
        self._load()
    
    def _load(self):
        """加载数据库"""
        if os.path.exists(self.db_path):
            with open(self.db_path, 'r') as f:
                data = json.load(f)
                for scenario_data in data.get('scenarios', []):
                    scenario = APIScenario.from_dict(scenario_data)
                    self.scenarios[scenario.scenario_id] = scenario
    
    def save(self):
        """保存数据库"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with open(self.db_path, 'w') as f:
            data = {
                'project_name': self.project_name,
                'scenarios': [s.to_dict() for s in self.scenarios.values()]
            }
            json.dump(data, f, indent=2)
    
    def add_scenario(self, scenario: APIScenario):
        """添加场景"""
        self.scenarios[scenario.scenario_id] = scenario
        self.save()
    
    def get_scenarios(self, target_function: str) -> List[APIScenario]:
        """获取目标函数的所有场景"""
        return [
            s for s in self.scenarios.values()
            if s.target_function == target_function
        ]
    
    def update_coverage(self, scenario_id: str, coverage_info: Dict):
        """更新场景的覆盖率信息"""
        if scenario_id in self.scenarios:
            self.scenarios[scenario_id].coverage_info.update(coverage_info)
            self.save()
```

## 五、总结

这个实现方案提供了：

1. **完整的类设计**: APIScenario, APIContract, 各种提取器和验证器
2. **清晰的模块划分**: scenario_modeling, contract_system, coverage_exploration, validation
3. **集成方案**: 如何集成到现有的 Prototyper 和 Supervisor
4. **数据库设计**: ScenarioDB 用于持久化场景数据

下一步可以按照这个设计逐步实现各个模块。

