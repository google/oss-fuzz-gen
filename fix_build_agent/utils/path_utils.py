# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Unified Path Parsing and Validation Tool (Upgrade Version)
Features workspace discovery, secure path guards, and dynamic whitelist loading.
Aligned strictly with the system's authorized read/write boundaries.
"""
import os
from pathlib import Path
from typing import List, Optional

import yaml


def detect_project_root() -> str:
  """
    Detects the workspace root by walking upwards from this file until finding
    'config/path_whitelist.yaml' or '.git'.
    Falls back to the environment variable PROJECT_ROOT or current working directory.
    """
  # 优先使用系统环境变量
  env_root = os.environ.get('PROJECT_ROOT')
  if env_root and os.path.isdir(env_root):
    return os.path.abspath(env_root)

  # 沿当前文件所在路径向上追溯寻找特征哨兵
  current_file_path = Path(__file__).resolve()
  for parent in [current_file_path] + list(current_file_path.parents):
    # 如果检测到了特征配置文件或 git 仓库，判定为项目根目录
    if (parent / "config" /
        "path_whitelist.yaml").is_file() or (parent / ".git").is_dir():
      return str(parent.resolve())

  # 最终降级兜底为当前 Python 执行的工作路径
  return os.path.abspath(os.getcwd())


def load_whitelist_config(config_path: Optional[str] = None) -> List[str]:
  """
    Loads allowed path prefixes from config/path_whitelist.yaml. Falls back to
    defaults if loading fails or the file is missing.
    Matches the strict read/write boundaries authorized by the user.
    """
  # 物理授权读写白名单（严格契约对齐）
  default_allowed = [
      'oss-fuzz/',
      'process/',  # 隐式覆盖 process/project, process/fixed, process/unfixed
      'generated_prompt_file/',
      'fuzz_build_log_file/',
      'success-fix-project/',
      'agent_logs/',
      'project_repair_trace.json',
      'repair_strategy.txt',
      'fix-success.txt',
      'projects.yaml',
      'solution.txt'
  ]

  if config_path is None:
    root_dir = detect_project_root()
    config_path = os.path.join(root_dir, "config", "path_whitelist.yaml")

  if not os.path.exists(config_path):
    return default_allowed

  try:
    with open(config_path, 'r', encoding='utf-8') as f:
      data = yaml.safe_load(f)
    if isinstance(data, dict) and "allowed_prefixes" in data:
      prefixes = data["allowed_prefixes"]
      if isinstance(prefixes, list):
        # 过滤空值并清理前后空格
        return [str(p).strip() for p in prefixes if p]
  except Exception:
    # 发生异常时静默降级，确保核心工作流稳定运行
    pass

  return default_allowed


# =====================================================================
# 模块层级初始化：动态缓存项目根路径与白名单，杜绝硬编码
# =====================================================================
DEFAULT_PROJECT_ROOT = detect_project_root()
DEFAULT_ALLOWED_PREFIXES = load_whitelist_config()


def normalize_patch_path(file_path: str, base_dir: Optional[str] = None) -> str:
  """
    Unified patch file path normalization: absolute path -> relative path.
    Uses relpath-based verification to ensure absolute cross-platform safety.

    Args:
        file_path: Original file path (absolute or relative)
        base_dir: Base directory, uses DEFAULT_PROJECT_ROOT by default

    Returns:
        Normalized relative path (using forward slashes)
    """
  if base_dir is None:
    base_dir = DEFAULT_PROJECT_ROOT

  if not file_path:
    return file_path

  # 统一斜杠与反斜杠格式
  file_path = file_path.replace('\\', '/')
  base_dir = base_dir.replace('\\', '/')

  # 转换为绝对路径进行无偏比对
  abs_path = os.path.abspath(file_path)
  abs_base = os.path.abspath(base_dir)

  try:
    # 利用 os.path.relpath 自动换算相对路径，防范复杂的深度越界
    rel_path = os.path.relpath(abs_path, abs_base)
    if not rel_path.startswith('..') and not os.path.isabs(rel_path):
      return rel_path.replace('\\', '/')
  except ValueError:
    # 处理 Windows 环境下跨盘符等异常边界
    pass

  return file_path


def validate_patch_path(file_path: str,
                        allowed_prefixes: Optional[List[str]] = None,
                        strict: bool = False) -> bool:
  """
    Whitelist validation: verify if the patch path is within the allowed range.
    Automatically loads allowed prefixes from path_whitelist.yaml by default.

    Args:
        file_path: File path to be validated
        allowed_prefixes: List of allowed path prefixes (relative path format)
        strict: Strict mode, log detailed details on failure

    Returns:
        bool: Whether the path is valid
    """
  if allowed_prefixes is None:
    allowed_prefixes = load_whitelist_config()

  # 规范化路径
  norm_path = normalize_patch_path(file_path)

  # 空路径、当前工作区目录，直接放行
  if norm_path in ('', '.', './'):
    return True

  # 进行白名单前缀比对
  for prefix in allowed_prefixes:
    prefix_norm = prefix.rstrip('/')
    if norm_path == prefix_norm or norm_path.startswith(prefix_norm + '/'):
      return True

  # 严格审查拦截，如果失败，通过错误处理器打印带标准纠错建议的提示
  if strict:
    import logging

    from utils.error_handler import format_path_error
    logger = logging.getLogger(__name__)
    logger.warning(
        format_path_error(original_path=file_path,
                          normalized_path=norm_path,
                          base_dir=DEFAULT_PROJECT_ROOT,
                          validation_passed=False,
                          extra_info={'allowed_prefixes': allowed_prefixes}))

  return False


def ensure_relative_path(file_path: str, base_dir: Optional[str] = None) -> str:
  """
    Ensures the path is relative for instruction validation.

    Raises:
        ValueError: When the path cannot be converted to a relative path
    """
  if base_dir is None:
    base_dir = DEFAULT_PROJECT_ROOT

  normalized = normalize_patch_path(file_path, base_dir)

  # 若归一化后仍为物理绝对路径（说明越界脱靶），抛出异常强硬阻断
  if os.path.isabs(normalized):
    raise ValueError(f"Path must be relative: '{file_path}' -> '{normalized}'. "
                     f"Expected relative to workspace root: {base_dir}")

  return normalized
