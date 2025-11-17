# LogicFuzz 架构优化方案

## 一、核心问题分析

### 问题 1: API Group 建模与覆盖率提升
**当前问题**：
- 只从 usage examples 提取 API 组合，缺少对"用户场景/文档期待场景"的系统性建模
- 覆盖率优化是后置的（运行后分析），缺少主动探索机制
- 没有区分不同场景下的 API 组合模式

**目标**：
- 建模多种用户场景下的 API 组合模式（API Scenario Model）
- 主动探索未覆盖的 API 组合，提高项目覆盖率
- 基于覆盖率反馈，动态调整 API 组合策略

### 问题 2: API 调用正确性保证
**当前问题**：
- 正确性验证主要在 crash 后（假阳性过滤），缺少事前验证
- 没有系统性的 API Contract 验证机制
- 缺少对参数约束、状态转换、资源管理的验证

**目标**：
- 在生成代码前验证 API 序列的正确性（Pre-Execution Validation）
- 建立 API Contract 系统，验证参数约束、状态转换、资源管理
- 减少假阳性，提高 crash 的可信度

---

## 二、新架构设计

### 2.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                    LogicFuzz 2.0 Architecture                    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: API Scenario Modeling & Discovery                     │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ Scenario Extractor│  │ Scenario Analyzer│  │ Scenario DB  │  │
│  │ - Usage examples │  │ - LLM analysis   │  │ - Scenarios  │  │
│  │ - Documentation  │  │ - Pattern mining │  │ - Coverage   │  │
│  │ - Test cases     │  │ - Clustering     │  │ - Statistics │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2: API Contract System                                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ Contract Extractor│  │ Contract Validator│ │ Contract DB  │  │
│  │ - Preconditions  │  │ - Type checking  │  │ - Contracts  │  │
│  │ - Postconditions │  │ - State machine  │  │ - Violations │  │
│  │ - Invariants     │  │ - Resource mgmt  │  │ - Fixes      │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3: Scenario-Based Code Generation                        │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ Scenario Selector│  │ Code Generator   │  │ Validator    │  │
│  │ - Coverage-based │  │ - Multi-scenario │  │ - Pre-exec   │  │
│  │ - Priority-based │  │ - Contract-aware │  │ - Contract   │  │
│  │ - Diversity-based│  │ - Template-based │  │ - Static     │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Layer 4: Coverage-Driven Exploration                           │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ Coverage Analyzer│  │ Scenario Explorer│  │ Feedback Loop│  │
│  │ - Path analysis  │  │ - Unexplored     │  │ - Update DB  │  │
│  │ - API coverage   │  │ - Combinations   │  │ - Prioritize │  │
│  │ - Gap detection  │  │ - Variations     │  │ - Learn      │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 核心组件设计

#### 组件 1: API Scenario Model (场景建模)

**功能**：建模用户场景/文档期待场景下的 API 组合模式

**设计**：
```python
class APIScenario:
    """表示一个用户场景下的 API 组合模式"""
    
    # 场景元数据
    scenario_id: str
    scenario_name: str  # e.g., "parse_and_validate", "create_and_destroy"
    scenario_type: str  # "usage_example", "documentation", "test_case", "inferred"
    confidence: float   # 0.0-1.0
    
    # API 序列
    api_sequence: List[APICall]  # 有序的 API 调用序列
    # APICall = {
    #   'function': str,
    #   'parameters': Dict[str, Any],
    #   'preconditions': List[str],
    #   'postconditions': List[str],
    #   'state_before': Dict,
    #   'state_after': Dict,
    # }
    
    # 场景特征
    context: Dict  # 场景上下文（输入类型、输出类型、错误处理等）
    coverage_info: Dict  # 该场景覆盖的代码路径
    frequency: int  # 在真实代码中出现的频率
    
    # 统计信息
    success_rate: float  # 该场景的成功率
    crash_rate: float    # 该场景的崩溃率
    false_positive_rate: float  # 该场景的假阳性率
```

**数据来源**：
1. **Usage Examples** (FuzzIntrospector): 真实代码中的使用模式
2. **Documentation**: API 文档中的示例代码
3. **Test Cases**: 项目测试用例中的 API 组合
4. **LLM Analysis**: 基于 API 语义推断的场景

**场景提取流程**：
```
1. 收集多源数据 (usage examples, docs, tests)
2. 提取 API 调用序列
3. 聚类相似的序列 → 场景模式
4. LLM 分析场景语义 → 场景命名和分类
5. 统计场景频率和覆盖率 → 场景优先级
6. 存储到 Scenario DB
```

#### 组件 2: API Contract System (契约系统) + Automata (自动机)

**功能**：定义和验证 API 的调用契约（前置条件、后置条件、不变量），使用自动机建模状态转换

**设计**：
```python
class APIContract:
    """API 调用契约"""
    
    function_name: str
    
    # 前置条件（调用前必须满足）
    preconditions: List[Precondition]
    # Precondition = {
    #   'type': 'not_null', 'valid_range', 'initialized', 'state_check',
    #   'parameter': str,  # 参数名
    #   'condition': str,  # 条件表达式
    #   'error_if_violated': str,  # 违反时的错误信息
    # }
    
    # 后置条件（调用后保证满足）
    postconditions: List[Postcondition]
    # Postcondition = {
    #   'type': 'return_not_null', 'state_changed', 'resource_allocated',
    #   'guarantee': str,  # 保证的内容
    # }
    
    # 状态转换（使用自动机建模）
    # 新增：资源状态机（Resource FSM）- 核心层
    resource_fsm: Optional[ResourceFSM]
    # ResourceFSM = {
    #   'states': {UNINITIALIZED, INITIALIZED, IN_USE, RELEASED, ERROR},
    #   'transitions': {(state, api_call) -> next_state},
    #   'initial_state': UNINITIALIZED,
    #   'accepting_states': {RELEASED},
    # }
    
    # 新增：API 序列状态机（Sequence FSM）- 扩展层
    sequence_fsm: Optional[SequenceFSM]
    # SequenceFSM = {
    #   'states': {START, CREATED, INITIALIZED, IN_USE, END, ...},
    #   'transitions': {(state, api_call) -> {next_states}},  # NFA
    #   'initial_state': START,
    #   'accepting_states': {END},
    # }
    
    # 资源管理
    resource_management: ResourceManagement
    # ResourceManagement = {
    #   'allocates': List[str],  # 分配的资源
    #   'requires': List[str],   # 需要的资源
    #   'cleanup': List[str],    # 清理函数
    # }
    
    # 参数约束
    parameter_constraints: Dict[str, ParameterConstraint]
    # ParameterConstraint = {
    #   'type': str,
    #   'valid_range': Tuple,
    #   'required': bool,
    #   'default_value': Any,
    # }
```

**自动机层次架构**：
1. **Resource FSM（资源状态机）** - 核心层，必须实现
   - 建模资源的生命周期：UNINITIALIZED → INITIALIZED → IN_USE → RELEASED
   - 检测资源管理错误（use-after-free、内存泄漏）
   - 覆盖 80%+ 的 API 场景

2. **Sequence FSM（API 序列状态机）** - 扩展层，推荐实现
   - 建模 API 调用的合法序列（支持条件分支、循环）
   - 生成多样化的合法 API 序列
   - 支持 NFA（非确定性有限自动机）

3. **Parameter FSM（参数状态机）** - 高级层，可选实现
   - 建模参数的有效状态（NULL → ALLOCATED → SET → VALIDATED）
   - 用于复杂参数设置场景

**契约提取来源**：
1. **SRS Data** (Function Analyzer 输出): 结构化需求规范
2. **Documentation**: API 文档中的约束说明
3. **Static Analysis**: 代码静态分析（参数检查、返回值检查）
4. **LLM Analysis**: 基于代码语义推断的契约

**契约验证流程（使用自动机）**：
```
1. 提取 API Contract (从 SRS、文档、静态分析、LLM)
2. 提取/构建自动机：
   a. 从 usage examples 提取资源状态机（Resource FSM）
   b. 从 API 序列提取序列状态机（Sequence FSM）
   c. 从参数设置提取参数状态机（Parameter FSM，可选）
3. 验证 API 序列的契约满足性：
   a. 使用 Resource FSM 验证资源生命周期（O(n) 复杂度）
   b. 使用 Sequence FSM 验证 API 序列合法性（支持 NFA）
   c. 检查每个 API 的前置条件是否满足
   d. 检查参数约束是否满足
4. 如果违反契约 → 生成修复建议（基于状态机错误信息）
5. 存储违反记录到 Contract DB (用于学习，优化状态机)
```

#### 组件 3: Scenario-Based Code Generation (基于场景的代码生成)

**功能**：基于场景模型生成代码，确保符合 API 契约

**设计**：
```python
class ScenarioBasedGenerator:
    """基于场景的代码生成器"""
    
    def generate(self, target_function: str, scenario: APIScenario) -> str:
        """
        基于场景生成代码
        
        流程：
        1. 选择场景（基于覆盖率、优先级、多样性）
        2. 验证场景的 API 序列是否符合契约
        3. 生成代码（使用场景中的 API 序列）
        4. 注入契约检查代码（运行时验证）
        5. 返回生成的代码
        """
        pass
    
    def select_scenario(self, target_function: str, 
                       coverage_info: Dict) -> APIScenario:
        """
        选择场景（基于覆盖率驱动）
        
        策略：
        1. 优先选择未覆盖的场景
        2. 优先选择高优先级场景（高频、高成功率）
        3. 优先选择多样性场景（与已生成代码不同）
        """
        pass
```

**场景选择策略**：
1. **Coverage-Based**: 优先选择覆盖未探索代码路径的场景
2. **Priority-Based**: 优先选择高频、高成功率的场景
3. **Diversity-Based**: 优先选择与已生成代码不同的场景

#### 组件 4: Pre-Execution Validation (执行前验证)

**功能**：在运行 fuzzer 前验证代码的正确性

**设计**：
```python
class PreExecutionValidator:
    """执行前验证器"""
    
    def validate(self, code: str, scenario: APIScenario) -> ValidationResult:
        """
        验证代码的正确性
        
        检查项：
        1. API 序列是否符合契约（静态分析）
        2. 参数类型是否匹配
        3. 状态转换是否正确
        4. 资源管理是否正确（init → use → cleanup）
        5. 前置条件是否满足（通过代码分析）
        """
        pass
    
    def inject_contract_checks(self, code: str, contracts: List[APIContract]) -> str:
        """
        注入契约检查代码（运行时验证）
        
        例如：
        ```c
        // Precondition check
        if (ctx == NULL) {
            // Log violation
            return 0;  // Early return
        }
        
        // API call
        result = target_function(ctx, data, size);
        
        // Postcondition check
        if (result == NULL) {
            // Log violation
        }
        ```
        """
        pass
```

**验证层次**：
1. **Static Analysis**: 静态代码分析（类型检查、控制流分析）
2. **Contract Validation**: 契约验证（前置条件、后置条件、状态转换）
3. **Runtime Checks**: 运行时检查（注入契约检查代码）

#### 组件 5: Coverage-Driven Scenario Exploration (覆盖率驱动的场景探索)

**功能**：基于覆盖率反馈，主动探索未覆盖的 API 组合

**设计**：
```python
class CoverageDrivenExplorer:
    """覆盖率驱动的场景探索器"""
    
    def explore(self, target_function: str, 
                current_coverage: Dict,
                scenario_db: ScenarioDB) -> List[APIScenario]:
        """
        探索未覆盖的场景
        
        流程：
        1. 分析当前覆盖率（哪些 API、哪些路径未覆盖）
        2. 识别覆盖缺口（API 组合、参数组合、状态组合）
        3. 生成新场景（基于覆盖缺口）
        4. 验证新场景的可行性（契约验证）
        5. 返回新场景列表
        """
        pass
    
    def identify_coverage_gaps(self, coverage: Dict) -> List[CoverageGap]:
        """
        识别覆盖缺口
        
        缺口类型：
        1. API 未覆盖：某些 API 从未被调用
        2. 参数组合未覆盖：某些参数组合从未被测试
        3. 状态组合未覆盖：某些状态转换从未被执行
        4. 路径未覆盖：某些代码路径从未被执行
        """
        pass
    
    def generate_scenario_variations(self, base_scenario: APIScenario,
                                    gap: CoverageGap) -> List[APIScenario]:
        """
        基于基础场景生成变体（填补覆盖缺口）
        
        变体策略：
        1. 参数变体：改变参数值、参数组合
        2. 序列变体：改变 API 调用顺序、添加/删除 API
        3. 状态变体：改变初始状态、中间状态
        4. 错误处理变体：添加错误处理、边界情况
        """
        pass
```

---

## 三、工作流程设计

### 3.1 整体工作流

```
┌─────────────────────────────────────────────────────────────┐
│  Phase 0: Scenario Discovery & Contract Extraction          │
│  (一次性或定期执行)                                           │
└─────────────────────────────────────────────────────────────┘
  ↓
  1. 提取场景 (Scenario Extractor)
     - 从 usage examples 提取
     - 从文档提取
     - 从测试用例提取
     - LLM 分析推断
  ↓
  2. 分析场景 (Scenario Analyzer)
     - 聚类相似场景
     - 提取场景模式
     - 计算场景优先级
  ↓
  3. 提取契约 (Contract Extractor)
     - 从 SRS 提取
     - 从文档提取
     - 静态分析提取
     - LLM 分析推断
  ↓
  4. 存储到数据库 (Scenario DB + Contract DB)

┌─────────────────────────────────────────────────────────────┐
│  Phase 1: Scenario-Based Generation                         │
└─────────────────────────────────────────────────────────────┘
  ↓
  1. 选择场景 (Scenario Selector)
     - 基于覆盖率选择未覆盖场景
     - 基于优先级选择高优先级场景
     - 基于多样性选择不同场景
  ↓
  2. 验证契约 (Contract Validator)
     - 检查 API 序列是否符合契约
     - 如果违反 → 修复或选择其他场景
  ↓
  3. 生成代码 (Code Generator)
     - 基于场景生成代码
     - 注入契约检查代码
  ↓
  4. 执行前验证 (Pre-Execution Validator)
     - 静态分析验证
     - 契约验证
     - 如果失败 → 返回步骤 2

┌─────────────────────────────────────────────────────────────┐
│  Phase 2: Execution & Coverage Analysis                     │
└─────────────────────────────────────────────────────────────┘
  ↓
  1. 运行 Fuzzer
  ↓
  2. 收集覆盖率 (Coverage Analyzer)
     - API 覆盖率
     - 路径覆盖率
     - 状态覆盖率
  ↓
  3. 分析 Crash (Crash Analyzer)
     - 如果 crash → 检查是否违反契约
     - 如果违反契约 → 假阳性（修复代码）
     - 如果符合契约 → 真实 bug

┌─────────────────────────────────────────────────────────────┐
│  Phase 3: Coverage-Driven Exploration                       │
└─────────────────────────────────────────────────────────────┘
  ↓
  1. 识别覆盖缺口 (Coverage Gap Detection)
     - 未覆盖的 API
     - 未覆盖的参数组合
     - 未覆盖的状态组合
     - 未覆盖的代码路径
  ↓
  2. 生成场景变体 (Scenario Variation Generation)
     - 基于覆盖缺口生成新场景
     - 验证新场景的可行性
  ↓
  3. 更新场景数据库 (Scenario DB Update)
     - 记录新场景
     - 更新场景统计信息
  ↓
  4. 返回 Phase 1 (继续生成)
```

### 3.2 关键决策点

#### 决策点 1: 场景选择
```
IF 存在未覆盖场景:
    选择未覆盖场景
ELIF 存在高优先级场景:
    选择高优先级场景
ELSE:
    选择多样性场景（与已生成代码不同）
```

#### 决策点 2: 契约违反处理
```
IF 契约违反:
    IF 可以自动修复:
        修复并继续
    ELIF 有替代场景:
        选择替代场景
    ELSE:
        记录违反 → 人工审查
```

#### 决策点 3: Crash 分析
```
IF crash:
    IF 违反契约:
        标记为假阳性 → 修复代码
    ELIF 符合契约:
        标记为真实 bug → 报告
    ELSE:
        深入分析（可能需要人工审查）
```

---

## 四、实现计划

### 4.1 阶段 1: 核心组件实现（3-4 周）

**任务 1.1: API Scenario Model**
- [ ] 实现 `APIScenario` 类
- [ ] 实现 `ScenarioExtractor` (从 usage examples 提取)
- [ ] 实现 `ScenarioAnalyzer` (聚类和分析)
- [ ] 实现 `ScenarioDB` (场景数据库)

**任务 1.2: API Contract System + Automata（核心）**
- [ ] 实现 `APIContract` 类
- [ ] 实现 `ContractExtractor` (从 SRS、文档提取)
- [ ] **实现 `ResourceFSM` 类（资源状态机）- 核心层**
  - [ ] 状态定义（UNINITIALIZED, INITIALIZED, IN_USE, RELEASED, ERROR）
  - [ ] 状态转换规则提取（从 usage examples）
  - [ ] 序列验证算法（O(n) 复杂度）
  - [ ] 错误检测和报告
- [ ] **实现 `SequenceFSM` 类（API 序列状态机）- 扩展层**
  - [ ] NFA 支持（条件分支、循环）
  - [ ] 路径生成算法
- [ ] 实现 `ContractValidator` (使用自动机验证)
- [ ] 实现 `ContractDB` (契约数据库，包含状态机)

**任务 1.3: Pre-Execution Validation**
- [ ] 实现 `PreExecutionValidator` (使用自动机验证)
- [ ] 实现契约检查代码注入
- [ ] 集成到代码生成流程

### 4.2 阶段 2: 场景生成与选择（2-3 周）

**任务 2.1: Scenario-Based Generation**
- [ ] 实现 `ScenarioBasedGenerator`
- [ ] 实现 `ScenarioSelector` (覆盖率驱动选择)
- [ ] 集成到 Prototyper

**任务 2.2: Coverage-Driven Exploration**
- [ ] 实现 `CoverageDrivenExplorer`
- [ ] 实现覆盖缺口识别
- [ ] 实现场景变体生成

### 4.3 阶段 3: 集成与优化（1-2 周）

**任务 3.1: 工作流集成**
- [ ] 集成到 LangGraph 工作流
- [ ] 更新 Supervisor 路由逻辑
- [ ] 更新 Session Memory

**任务 3.2: 评估与优化**
- [ ] 评估场景覆盖率提升
- [ ] 评估假阳性率降低
- [ ] 优化场景选择策略

---

## 五、预期效果

### 5.1 覆盖率提升

**目标**：
- API 覆盖率提升 20-30%
- 代码路径覆盖率提升 15-25%
- 状态组合覆盖率提升 30-40%

**实现方式**：
- 主动探索未覆盖的 API 组合
- 基于覆盖率反馈生成场景变体
- 覆盖更多用户场景

### 5.2 假阳性率降低

**目标**：
- 假阳性率降低 50-70%（通过 Resource FSM 可降低 30-40%）
- Crash 可信度提升 80%+

**实现方式**：
- **自动机验证**：使用 Resource FSM 检测资源管理错误（use-after-free、内存泄漏）
- 执行前验证 API 序列的正确性（基于状态机）
- 契约检查减少 API 误用
- 运行时契约检查捕获违反

### 5.3 代码质量提升

**目标**：
- 编译成功率提升 10-15%
- 代码可维护性提升

**实现方式**：
- 基于真实场景生成代码
- 契约验证确保代码正确性
- 场景数据库积累知识

---

## 六、关键技术挑战

### 挑战 1: 场景提取的准确性

**问题**：如何准确提取用户场景？

**解决方案**：
- 多源数据融合（usage examples + docs + tests）
- LLM 辅助分析场景语义
- 聚类算法识别场景模式

### 挑战 2: 契约提取的完整性 + 状态机构建

**问题**：如何完整提取 API 契约？如何构建准确的状态机？

**解决方案**：
- 结合 SRS、文档、静态分析、LLM
- **从 usage examples 提取状态机**：分析真实代码中的状态转换模式
- **增量学习**：从违反记录中学习，优化状态机
- **多源融合**：结合 usage examples、SRS、文档构建状态机
- 人工审查关键契约和状态机

### 挑战 3: 场景选择的效率

**问题**：如何高效选择场景？

**解决方案**：
- 基于覆盖率的优先级排序
- 缓存场景选择结果
- 并行生成多个场景变体

### 挑战 4: 契约验证的性能

**问题**：契约验证是否会影响性能？

**解决方案**：
- 静态分析为主，运行时检查为辅
- 可配置的检查级别（严格/宽松）
- 优化验证算法

---

## 七、总结

### 核心创新点

1. **API Scenario Model**: 系统性建模用户场景下的 API 组合模式
2. **API Contract System + Automata**: 完整的 API 契约定义和验证机制，使用自动机建模状态转换
3. **Resource FSM（资源状态机）**: 核心层，建模资源生命周期，检测资源管理错误
4. **Sequence FSM（API 序列状态机）**: 扩展层，支持条件分支、循环，生成多样化序列
5. **Coverage-Driven Exploration**: 主动探索未覆盖的 API 组合
6. **Pre-Execution Validation**: 执行前验证（基于自动机），减少假阳性

### 关键优势

1. **覆盖率提升**: 主动探索未覆盖场景，提高项目覆盖率
2. **假阳性降低**: 契约验证确保 API 调用正确性
3. **可扩展性**: 场景数据库可以积累知识，持续改进
4. **可维护性**: 基于场景的代码生成，代码质量更高

### 下一步行动

1. **立即开始**: 实现 API Scenario Model 和 API Contract System
2. **快速迭代**: 先实现核心功能，再逐步优化
3. **评估验证**: 每个阶段都要评估效果，及时调整

