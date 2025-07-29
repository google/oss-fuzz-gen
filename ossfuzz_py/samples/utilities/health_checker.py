#!/usr/bin/env python3
# Copyright 2025 Google LLC
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
# pylint: disable=line-too-long,unused-import,unused-variable,redefined-outer-name
"""
OSS-Fuzz SDK Health Checker Utility

This utility provides comprehensive health checking for the OSS-Fuzz SDK
environment, components, and configuration.

What this utility covers:
- SDK installation and import verification
- Component availability checking
- Configuration validation
- Environment variable verification
- Storage backend connectivity
- Performance benchmarking
- Dependency checking

Usage:
    python health_checker.py [--project PROJECT_NAME] [--config CONFIG_FILE] [--verbose]
"""

import argparse
import os
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

# Add the parent directory to the path so we can import the SDK
sys.path.append(str(Path(__file__).parent.parent.parent))

# Global imports to avoid possibly unbound variables
try:
  from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK
except ImportError:
  OSSFuzzSDK = None


class HealthChecker:
  """Comprehensive health checker for OSS-Fuzz SDK."""

  def __init__(self, project_name='health_check_project', verbose=False):
    """Initialize health checker."""
    self.project_name = project_name
    self.verbose = verbose
    self.results = {}
    self.start_time = time.time()

  def log(self, message, level='INFO'):
    """Log message with timestamp."""
    if self.verbose or level in ['ERROR', 'WARNING']:
      timestamp = datetime.now().strftime('%H:%M:%S')
      print(f"[{timestamp}] {level}: {message}")

  def check_sdk_installation(self):
    """Check if the OSS-Fuzz SDK is properly installed."""
    print("🔍 Checking SDK Installation")
    print("-" * 28)

    checks = {'sdk_import': False, 'core_classes': False, 'version_info': False}

    # Test SDK import
    try:
      from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK
      checks['sdk_import'] = True
      self.log("SDK import successful")
      print("   ✅ SDK import: Success")
    except ImportError as e:
      self.log(f"SDK import failed: {e}", 'ERROR')
      print(f"   ❌ SDK import: Failed - {e}")

    # Test core classes import
    try:
      from ossfuzz_py.core.ossfuzz_sdk import (BuildOptions, BuildResult,
                                               PipelineOptions, PipelineResult,
                                               RunOptions, RunResult, SDKConfig)
      checks['core_classes'] = True
      self.log("Core classes import successful")
      print("   ✅ Core classes: Success")
    except ImportError as e:
      self.log(f"Core classes import failed: {e}", 'ERROR')
      print(f"   ❌ Core classes: Failed - {e}")

    # Test version information
    try:
      # Try to get version info if available
      import ossfuzz_py
      version = getattr(ossfuzz_py, '__version__', 'Unknown')
      checks['version_info'] = True
      self.log(f"SDK version: {version}")
      print(f"   ✅ Version info: {version}")
    except Exception as e:
      self.log(f"Version info unavailable: {e}", 'WARNING')
      print("   ⚠️  Version info: Unavailable")

    self.results['sdk_installation'] = checks
    return all(checks.values())

  def check_environment_variables(self):
    """Check environment variable configuration."""
    print("\n🌍 Checking Environment Variables")
    print("-" * 33)

    env_vars = {
        'OSSFUZZ_HISTORY_STORAGE_BACKEND': {
            'required': False,
            'default': 'local',
            'description': 'Storage backend type'
        },
        'OSSFUZZ_HISTORY_STORAGE_PATH': {
            'required': False,
            'default': '/tmp/ossfuzz_data',
            'description': 'Local storage path'
        },
        'GCS_BUCKET_NAME': {
            'required': False,
            'default': None,
            'description': 'GCS bucket for cloud storage'
        },
        'WORK_DIR': {
            'required': False,
            'default': '/tmp',
            'description': 'Working directory'
        },
        'OSS_FUZZ_DIR': {
            'required': False,
            'default': None,
            'description': 'OSS-Fuzz repository directory'
        }
    }

    env_status = {}

    for var_name, var_info in env_vars.items():
      value = os.environ.get(var_name)

      if value:
        env_status[var_name] = {
            'set': True,
            'value': value,
            'status': 'configured'
        }
        self.log(f"{var_name} = {value}")
        print(f"   ✅ {var_name}: {value}")
      elif var_info['required']:
        env_status[var_name] = {
            'set': False,
            'value': None,
            'status': 'missing_required'
        }
        self.log(f"{var_name} is required but not set", 'ERROR')
        print(f"   ❌ {var_name}: Required but not set")
      else:
        default = var_info['default']
        env_status[var_name] = {
            'set': False,
            'value': default,
            'status': 'using_default'
        }
        self.log(f"{var_name} using default: {default}")
        print(f"   ⚠️  {var_name}: Using default ({default})")

    self.results['environment_variables'] = env_status
    return True

  def check_sdk_initialization(self):
    """Check SDK initialization with different configurations."""
    print("\n⚙️ Checking SDK Initialization")
    print("-" * 30)

    init_tests = {
        'default_config': False,
        'custom_config': False,
        'config_object': False
    }

    # Test 1: Default configuration
    try:
      from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK
      sdk = OSSFuzzSDK(self.project_name)
      init_tests['default_config'] = True
      self.log("Default configuration initialization successful")
      print("   ✅ Default config: Success")
    except Exception as e:
      self.log(f"Default configuration failed: {e}", 'ERROR')
      print(f"   ❌ Default config: Failed - {e}")

    # Test 2: Custom dictionary configuration
    try:
      config_dict = {
          'storage_backend': 'local',
          'storage_path': tempfile.mkdtemp(prefix='health_check_'),
          'log_level': 'INFO'
      }
      if OSSFuzzSDK is not None:  # type: ignore
        sdk = OSSFuzzSDK(self.project_name, config_dict)  # type: ignore
      else:
        raise ImportError("OSSFuzzSDK not available")
      init_tests['custom_config'] = True
      self.log("Custom dictionary configuration successful")
      print("   ✅ Custom config: Success")
    except Exception as e:
      self.log(f"Custom configuration failed: {e}", 'ERROR')
      print(f"   ❌ Custom config: Failed - {e}")

    # Test 3: SDKConfig object
    try:
      from ossfuzz_py.core.ossfuzz_sdk import SDKConfig
      sdk_config = SDKConfig(
          storage_backend='local',
          storage_path=tempfile.mkdtemp(prefix='health_check_obj_'),
          log_level='DEBUG')
      if OSSFuzzSDK is not None:  # type: ignore
        sdk = OSSFuzzSDK(self.project_name, sdk_config)  # type: ignore
      else:
        raise ImportError("OSSFuzzSDK not available")
      init_tests['config_object'] = True
      self.log("SDKConfig object initialization successful")
      print("   ✅ Config object: Success")
    except Exception as e:
      self.log(f"SDKConfig object failed: {e}", 'ERROR')
      print(f"   ❌ Config object: Failed - {e}")

    self.results['sdk_initialization'] = init_tests
    return any(init_tests.values())

  def check_component_availability(self):
    """Check availability of SDK components."""
    print("\n🔧 Checking Component Availability")
    print("-" * 34)

    try:
      from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK, SDKConfig

      config = SDKConfig(
          storage_backend='local',
          storage_path=tempfile.mkdtemp(prefix='health_check_comp_'),
          log_level='WARNING'  # Reduce noise
      )

      sdk = OSSFuzzSDK(self.project_name, config)

      components = {
          'Storage Manager': getattr(sdk, 'storage', None),
          'Result Manager': getattr(sdk, 'result_manager', None),
          'Benchmark Manager': getattr(sdk, 'benchmark_manager', None),
          'Build History': getattr(sdk, 'build_history', None),
          'Coverage History': getattr(sdk, 'coverage_history', None),
          'Crash History': getattr(sdk, 'crash_history', None),
          'Corpus History': getattr(sdk, 'corpus_history', None),
          'Local Builder': getattr(sdk, 'local_builder', None),
          'Local Runner': getattr(sdk, 'local_runner', None),
      }

      component_status = {}
      available_count = 0

      for name, component in components.items():
        is_available = component is not None
        component_status[name] = {
            'available': is_available,
            'type': type(component).__name__ if component else None
        }

        if is_available:
          available_count += 1
          self.log(f"{name} is available")
          print(f"   ✅ {name}: Available")
        else:
          self.log(f"{name} is not available", 'WARNING')
          print(f"   ⚠️  {name}: Not available")

      print(
          f"\n   📊 Component Summary: {available_count}/{len(components)} available"
      )

      self.results['component_availability'] = {
          'components': component_status,
          'available_count': available_count,
          'total_count': len(components),
          'availability_rate': available_count / len(components)
      }

      return available_count > 0

    except Exception as e:
      self.log(f"Component availability check failed: {e}", 'ERROR')
      print(f"   ❌ Component check failed: {e}")
      return False

  def check_basic_operations(self):
    """Check basic SDK operations."""
    print("\n🎯 Checking Basic Operations")
    print("-" * 27)

    operations = {
        'project_summary': False,
        'list_benchmarks': False,
        'system_metrics': False,
        'benchmark_metrics': False
    }

    try:
      from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK, SDKConfig

      config = SDKConfig(
          storage_backend='local',
          storage_path=tempfile.mkdtemp(prefix='health_check_ops_'),
          log_level='ERROR'  # Minimize noise
      )

      sdk = OSSFuzzSDK(self.project_name, config)

      # Test project summary
      try:
        summary = sdk.get_project_summary()
        operations['project_summary'] = True
        self.log("Project summary operation successful")
        print("   ✅ Project summary: Success")
      except Exception as e:
        self.log(f"Project summary failed: {e}", 'WARNING')
        print(f"   ⚠️  Project summary: Failed - {e}")

      # Test list benchmarks
      try:
        benchmarks = sdk.list_benchmarks()
        operations['list_benchmarks'] = True
        self.log(f"List benchmarks successful ({len(benchmarks)} found)")
        print(f"   ✅ List benchmarks: Success ({len(benchmarks)} found)")
      except Exception as e:
        self.log(f"List benchmarks failed: {e}", 'WARNING')
        print(f"   ⚠️  List benchmarks: Failed - {e}")

      # Test system metrics
      try:
        metrics = sdk.get_system_metrics()
        operations['system_metrics'] = True
        self.log("System metrics operation successful")
        print("   ✅ System metrics: Success")
      except Exception as e:
        self.log(f"System metrics failed: {e}", 'WARNING')
        print(f"   ⚠️  System metrics: Failed - {e}")

      # Test benchmark metrics
      try:
        metrics = sdk.get_benchmark_metrics('test_benchmark')
        operations['benchmark_metrics'] = True
        self.log("Benchmark metrics operation successful")
        print("   ✅ Benchmark metrics: Success")
      except Exception as e:
        self.log(f"Benchmark metrics failed: {e}", 'WARNING')
        print(f"   ⚠️  Benchmark metrics: Failed - {e}")

    except Exception as e:
      self.log(f"Basic operations check failed: {e}", 'ERROR')
      print(f"   ❌ Operations check failed: {e}")

    self.results['basic_operations'] = operations
    return any(operations.values())

  def check_dependencies(self):
    """Check optional dependencies."""
    print("\n📦 Checking Dependencies")
    print("-" * 22)

    dependencies = {
        'pandas': {
            'required': False,
            'description': 'Data analysis and manipulation',
            'import_name': 'pandas'
        },
        'pydantic': {
            'required': False,
            'description': 'Data validation and settings management',
            'import_name': 'pydantic'
        },
        'yaml': {
            'required': False,
            'description': 'YAML file parsing',
            'import_name': 'yaml'
        },
        'chardet': {
            'required': False,
            'description': 'Character encoding detection',
            'import_name': 'chardet'
        }
    }

    dep_status = {}

    for dep_name, dep_info in dependencies.items():
      try:
        __import__(dep_info['import_name'])
        dep_status[dep_name] = {'available': True, 'status': 'installed'}
        self.log(f"{dep_name} is available")
        print(f"   ✅ {dep_name}: Installed")
      except ImportError:
        dep_status[dep_name] = {'available': False, 'status': 'missing'}
        if dep_info['required']:
          self.log(f"{dep_name} is required but missing", 'ERROR')
          print(f"   ❌ {dep_name}: Required but missing")
        else:
          self.log(f"{dep_name} is optional and missing", 'WARNING')
          print(f"   ⚠️  {dep_name}: Optional, not installed")

    self.results['dependencies'] = dep_status
    return True

  def run_performance_test(self):
    """Run basic performance test."""
    print("\n⚡ Running Performance Test")
    print("-" * 26)

    try:
      from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK, SDKConfig

      config = SDKConfig(
          storage_backend='local',
          storage_path=tempfile.mkdtemp(prefix='health_check_perf_'),
          log_level='ERROR')

      # Test SDK initialization time
      start_time = time.time()
      sdk = OSSFuzzSDK(self.project_name, config)
      init_time = time.time() - start_time

      # Test basic operations time
      start_time = time.time()
      summary = sdk.get_project_summary()
      benchmarks = sdk.list_benchmarks()
      metrics = sdk.get_system_metrics()
      ops_time = time.time() - start_time

      performance = {
          'initialization_time': init_time,
          'operations_time': ops_time,
          'total_time': init_time + ops_time
      }

      print(f"   ✅ SDK initialization: {init_time:.3f}s")
      print(f"   ✅ Basic operations: {ops_time:.3f}s")
      print(f"   ✅ Total time: {performance['total_time']:.3f}s")

      # Performance assessment
      if performance['total_time'] < 1.0:
        print("   🚀 Performance: Excellent")
      elif performance['total_time'] < 3.0:
        print("   ✅ Performance: Good")
      elif performance['total_time'] < 10.0:
        print("   ⚠️  Performance: Acceptable")
      else:
        print("   ❌ Performance: Poor")

      self.results['performance'] = performance
      return True

    except Exception as e:
      self.log(f"Performance test failed: {e}", 'ERROR')
      print(f"   ❌ Performance test failed: {e}")
      return False

  def generate_health_report(self):
    """Generate comprehensive health report."""
    print("\n📊 Health Check Report")
    print("=" * 22)

    total_time = time.time() - self.start_time

    # Overall status
    checks = [
        self.results.get('sdk_installation', {}).get('sdk_import', False),
        self.results.get('sdk_initialization', {}).get('default_config', False),
        any(
            self.results.get('component_availability',
                             {}).get('components', {}).values()),
        any(self.results.get('basic_operations', {}).values())
    ]

    overall_status = sum(checks) / len(checks)

    print("🏥 Overall Health: ", end="")
    if overall_status >= 0.8:
      print("🟢 Excellent")
    elif overall_status >= 0.6:
      print("🟡 Good")
    elif overall_status >= 0.4:
      print("🟠 Fair")
    else:
      print("🔴 Poor")

    print(f"⏱️  Total check time: {total_time:.2f}s")
    print(f"📅 Check timestamp: {datetime.now().isoformat()}")

    # Detailed results
    print("\n📋 Detailed Results:")

    # SDK Installation
    sdk_install = self.results.get('sdk_installation', {})
    sdk_score = sum(
        sdk_install.values()) / len(sdk_install) if sdk_install else 0
    print(f"   SDK Installation: {sdk_score:.1%}")

    # Component Availability
    comp_avail = self.results.get('component_availability', {})
    comp_score = comp_avail.get('availability_rate', 0)
    print(
        f"   Component Availability: {comp_score:.1%} ({comp_avail.get('available_count', 0)}/{comp_avail.get('total_count', 0)})"
    )

    # Basic Operations
    basic_ops = self.results.get('basic_operations', {})
    ops_score = sum(basic_ops.values()) / len(basic_ops) if basic_ops else 0
    print(f"   Basic Operations: {ops_score:.1%}")

    # Dependencies
    deps = self.results.get('dependencies', {})
    deps_available = sum(1 for d in deps.values() if d.get('available', False))
    deps_total = len(deps)
    deps_score = deps_available / deps_total if deps_total > 0 else 0
    print(
        f"   Optional Dependencies: {deps_score:.1%} ({deps_available}/{deps_total})"
    )

    # Performance
    perf = self.results.get('performance', {})
    if perf:
      total_perf_time = perf.get('total_time', 0)
      print(f"   Performance: {total_perf_time:.3f}s")

    # Recommendations
    print("\n💡 Recommendations:")

    if not sdk_install.get('sdk_import', False):
      print("   • Install the OSS-Fuzz SDK: pip install ossfuzz-py")

    if comp_score < 0.5:
      print("   • Check component dependencies and configuration")

    if ops_score < 0.5:
      print("   • Verify environment variables and storage configuration")

    if deps_score < 0.5:
      print("   • Install optional dependencies for full functionality:")
      print("     pip install pandas pydantic yaml chardet")

    if perf.get('total_time', 0) > 5.0:
      print("   • Consider optimizing configuration for better performance")

    return overall_status


def main():
  """Main function for health checker utility."""
  parser = argparse.ArgumentParser(description='OSS-Fuzz SDK Health Checker')
  parser.add_argument(
      '--project',
      default='health_check_project',
      help='Project name for testing (default: health_check_project)')
  parser.add_argument('--verbose',
                      action='store_true',
                      help='Enable verbose logging')

  args = parser.parse_args()

  print("🏥 OSS-Fuzz SDK Health Checker")
  print("=" * 35)
  print(f"Project: {args.project}")
  print(f"Timestamp: {datetime.now().isoformat()}")

  # Initialize health checker
  checker = HealthChecker(args.project, args.verbose)

  # Run all health checks
  checker.check_sdk_installation()
  checker.check_environment_variables()
  checker.check_sdk_initialization()
  checker.check_component_availability()
  checker.check_basic_operations()
  checker.check_dependencies()
  checker.run_performance_test()

  # Generate final report
  overall_health = checker.generate_health_report()

  # Exit with appropriate code
  if overall_health >= 0.8:
    print("\n🎉 Health check completed successfully!")
    sys.exit(0)
  elif overall_health >= 0.4:
    print("\n⚠️  Health check completed with warnings.")
    sys.exit(0)
  else:
    print("\n❌ Health check found significant issues.")
    sys.exit(1)


if __name__ == '__main__':
  main()
