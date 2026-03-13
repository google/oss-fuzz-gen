#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License a
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# pylint: disable=invalid-name,line-too-long,redefined-outer-name,unused-import,unused-variable
"""
OSS-Fuzz SDK Simple Benchmark Example

This example demonstrates how to work with a single benchmark,
including building, running, and analyzing results.

What this example covers:
- Creating and configuring a benchmark
- Building a fuzz target
- Running a benchmark
- Analyzing results and metrics
- Basic error handling and troubleshooting

Prerequisites:
- OSS-Fuzz SDK installed: pip install ossfuzz-py
- Basic configuration (see 02_configuration.py)
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the parent directory to the path so we can import the SDK
sys.path.append(str(Path(__file__).parent.parent.parent))


def create_sample_fuzz_target():
  """Create a sample fuzz target for demonstration."""
  print("📝 Creating Sample Fuzz Target")
  print("-" * 30)

  # Sample fuzz target source code
  fuzz_target_source = '''
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Simple vulnerable function for demonstration
int vulnerable_function(const uint8_t* data, size_t size) {
    if (size < 4) return 0;

    // Simulate a buffer overflow vulnerability
    char buffer[10];
    if (data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        // This would cause a buffer overflow in real code
        memcpy(buffer, data, size);  // Intentionally vulnerable
        return 1;
    }

    return 0;
}

// LibFuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    return vulnerable_function(data, size);
}
'''

  # Sample build script
  build_script = '''
#!/bin/bash
# Simple build script for the sample fuzz target

# Compile the fuzz target
$CXX $CXXFLAGS -o $OUT/sample_target sample_target.cpp $LIB_FUZZING_ENGINE

echo "Build completed successfully"
'''

  # Create target specification
  target_spec = {
      'name':
          'sample_target',
      'source_code':
          fuzz_target_source,
      'build_script':
          build_script,
      'project_name':
          'sample_project',
      'language':
          'c++',
      'function_signature':
          'int vulnerable_function(const uint8_t* data, size_t size)',
  }

  print("✅ Sample fuzz target created:")
  print(f"   Name: {target_spec['name']}")
  print(f"   Language: {target_spec['language']}")
  print(f"   Project: {target_spec['project_name']}")
  print(f"   Source code: {len(target_spec['source_code'])} characters")
  print(f"   Build script: {len(target_spec['build_script'])} characters")

  return target_spec


def demonstrate_build_operations(sdk, target_spec):
  """Demonstrate build operations with the sample target."""
  print("\n🏗️ Build Operations")
  print("-" * 20)

  try:
    from ossfuzz_py.core.ossfuzz_sdk import BuildOptions

    # Create build options
    build_options = BuildOptions(
        sanitizer='address',  # Use AddressSanitizer
        architecture='x86_64',
        timeout_seconds=1800,  # 30 minutes
        environment_vars={
            'FUZZING_ENGINE': 'libfuzzer',
            'SANITIZER': 'address'
        })

    print("1. Build Configuration:")
    print(f"   ✅ Sanitizer: {build_options.sanitizer}")
    print(f"   ✅ Architecture: {build_options.architecture}")
    print(f"   ✅ Timeout: {build_options.timeout_seconds}s")
    print(f"   ✅ Environment vars: {len(build_options.environment_vars)}")

    # Attempt to build the fuzz target
    print("\n2. Building Fuzz Target:")
    print(f"   Attempting to build: {target_spec['name']}")

    build_result = sdk.build_fuzz_target(target_spec, build_options)

    if build_result.success:
      print("   ✅ Build completed successfully!")
      print(f"      Build ID: {build_result.build_id}")
      print(f"      Message: {build_result.message}")
      print(f"      Artifacts: {len(build_result.artifacts)} items")

      # Show artifacts if available
      if build_result.artifacts:
        print("      Available artifacts:")
        for name, path in build_result.artifacts.items():
          print(f"        - {name}: {path}")
    else:
      print(f"   ⚠️  Build failed: {build_result.message}")
      print("      This is expected in a demo environment without build tools")

    # Check build status
    print("\n3. Checking Build Status:")
    build_status = sdk.get_build_status(build_result.build_id)
    print(f"   Build ID: {build_status['build_id']}")
    print(f"   Status: {build_status['status']}")
    print(f"   Message: {build_status['message']}")

    return build_result

  except Exception as e:
    print(f"❌ Build operations failed: {e}")
    return None


def demonstrate_run_operations(sdk, target_spec, build_result):
  """Demonstrate run operations with the sample target."""
  print("\n🏃 Run Operations")
  print("-" * 17)

  try:
    from ossfuzz_py.core.ossfuzz_sdk import RunOptions

    # Create run options
    run_options = RunOptions(
        duration_seconds=300,  # 5 minutes
        timeout_seconds=25,  # 25 seconds per input
        max_memory_mb=1024,  # 1GB memory limit
        detect_leaks=True,
        extract_coverage=True,
        output_dir='fuzz_output')

    print("1. Run Configuration:")
    print(f"   ✅ Duration: {run_options.duration_seconds}s")
    print(f"   ✅ Timeout per input: {run_options.timeout_seconds}s")
    print(f"   ✅ Memory limit: {run_options.max_memory_mb}MB")
    print(f"   ✅ Leak detection: {run_options.detect_leaks}")
    print(f"   ✅ Coverage extraction: {run_options.extract_coverage}")

    # Attempt to run the fuzz target
    print("\n2. Running Fuzz Target:")

    if build_result and build_result.success:
      print(f"   Using build artifacts from: {build_result.build_id}")
      build_metadata = build_result.artifacts
    else:
      print("   Using mock build metadata (build failed)")
      build_metadata = {'mock': 'metadata'}

    run_result = sdk.run_fuzz_target(target_spec, build_metadata, run_options)

    if run_result.success:
      print("   ✅ Run completed successfully!")
      print(f"      Run ID: {run_result.run_id}")
      print(f"      Crashes detected: {run_result.crashes}")
      print(f"      Message: {run_result.message}")

      # Show coverage data if available
      if run_result.coverage_data:
        print("      Coverage data:")
        for key, value in run_result.coverage_data.items():
          print(f"        - {key}: {value}")
    else:
      print(f"   ⚠️  Run failed: {run_result.message}")
      print(
          "      This is expected in a demo environment without execution tools"
      )

    # Check run status
    print("\n3. Checking Run Status:")
    run_status = sdk.get_run_status(run_result.run_id)
    print(f"   Run ID: {run_status['run_id']}")
    print(f"   Status: {run_status['status']}")
    print(f"   Message: {run_status['message']}")

    return run_result

  except Exception as e:
    print(f"❌ Run operations failed: {e}")
    return None


def demonstrate_benchmark_operations(sdk):
  """Demonstrate benchmark-specific operations."""
  print("\n🎯 Benchmark Operations")
  print("-" * 23)

  benchmark_id = 'sample_benchmark_001'

  try:
    # 1. Create a benchmark
    print("1. Creating Benchmark:")
    benchmark_spec = {
        'id':
            benchmark_id,
        'project':
            'sample_project',
        'language':
            'c++',
        'function_name':
            'vulnerable_function',
        'function_signature':
            'int vulnerable_function(const uint8_t* data, size_t size)',
        'return_type':
            'int',
        'target_path':
            '/sample/target.h',
        'description':
            'Sample benchmark for demonstration'
    }

    success = sdk.create_benchmark(benchmark_spec)
    if success:
      print(f"   ✅ Benchmark created: {benchmark_id}")
    else:
      print("   ⚠️  Benchmark creation failed (expected in demo)")

    # 2. List benchmarks
    print("\n2. Listing Benchmarks:")
    benchmarks = sdk.list_benchmarks()
    print(f"   Found {len(benchmarks)} benchmarks")

    if benchmarks:
      for i, benchmark in enumerate(benchmarks[:3]):
        print(f"     {i+1}. {benchmark.get('id', 'Unknown')}")
    else:
      print("   No benchmarks found (this is normal for a new setup)")

    # 3. Run benchmark (build + run)
    print("\n3. Running Complete Benchmark:")
    from ossfuzz_py.core.ossfuzz_sdk import RunOptions

    run_options = RunOptions(duration_seconds=60)  # Short run for demo
    benchmark_result = sdk.run_benchmark(benchmark_id, run_options)

    if benchmark_result.success:
      print(f"   ✅ Benchmark run completed: {benchmark_result.run_id}")
      print(f"      Crashes: {benchmark_result.crashes}")
    else:
      print(f"   ⚠️  Benchmark run failed: {benchmark_result.message}")
      print("      This is expected in a demo environment")

    return benchmark_id

  except Exception as e:
    print(f"❌ Benchmark operations failed: {e}")
    return benchmark_id


def demonstrate_result_analysis(sdk, benchmark_id):
  """Demonstrate result analysis and metrics."""
  print("\n📊 Result Analysis")
  print("-" * 18)

  try:
    # 1. Get benchmark metrics
    print("1. Benchmark Metrics:")
    metrics = sdk.get_benchmark_metrics(benchmark_id)

    if metrics:
      print(f"   ✅ Retrieved metrics for {benchmark_id}:")
      print(f"      Compiles: {metrics.get('compiles', 'Unknown')}")
      print(f"      Crashes: {metrics.get('crashes', 'Unknown')}")
      print(f"      Coverage: {metrics.get('coverage', 'Unknown')}")
      print(
          f"      Line coverage diff: {metrics.get('line_coverage_diff', 'Unknown')}"
      )
      print(f"      Trial: {metrics.get('trial', 'Unknown')}")
    else:
      print(f"   ⚠️  No metrics available for {benchmark_id}")
      print("      This is normal for a new benchmark")

    # 2. Get build success rate
    print("\n2. Build Success Rate:")
    success_rate = sdk.get_build_success_rate(benchmark_id, days=7)
    print(f"   7-day build success rate: {success_rate:.2%}")

    # 3. Get crash summary
    print("\n3. Crash Summary:")
    crash_summary = sdk.get_crash_summary(benchmark_id, days=7)

    if crash_summary:
      print(f"   Total crashes: {crash_summary.get('total_crashes', 0)}")
      print(f"   Unique crashes: {crash_summary.get('unique_crashes', 0)}")
      print(f"   Crash rate: {crash_summary.get('crash_rate', 0.0):.2%}")
    else:
      print("   No crash data available")

    # 4. Get coverage trend
    print("\n4. Coverage Trend:")
    coverage_trend = sdk.get_coverage_trend(benchmark_id, days=7)

    if isinstance(coverage_trend, list) and coverage_trend:
      print(f"   Coverage data points: {len(coverage_trend)}")
      for point in coverage_trend[-3:]:  # Show last 3 points
        date = point.get('date', 'Unknown')
        coverage = point.get('coverage', 0)
        print(f"     {date}: {coverage}%")
    else:
      print("   No coverage trend data available")

    # 5. Get benchmark result
    print("\n5. Latest Benchmark Result:")
    result = sdk.get_benchmark_result(benchmark_id)

    if result:
      print("   ✅ Latest result found:")
      print(f"      Trial: {getattr(result, 'trial', 'Unknown')}")
      print(
          f"      Build successful: {getattr(result, 'is_build_successful', lambda: 'Unknown')()}"
      )
      print(
          f"      Run successful: {getattr(result, 'is_run_successful', lambda: 'Unknown')()}"
      )
    else:
      print("   No result data available")

  except Exception as e:
    print(f"❌ Result analysis failed: {e}")


def demonstrate_error_handling(sdk):
  """Demonstrate error handling and troubleshooting."""
  print("\n🔧 Error Handling & Troubleshooting")
  print("-" * 35)

  # 1. Component availability
  print("1. Component Availability Check:")
  components = {
      'Result Manager': getattr(sdk, 'result_manager', None),
      'Benchmark Manager': getattr(sdk, 'benchmark_manager', None),
      'Local Builder': getattr(sdk, 'local_builder', None),
      'Local Runner': getattr(sdk, 'local_runner', None),
  }

  for name, component in components.items():
    status = "✅ Available" if component is not None else "⚠️  Not available"
    print(f"   {status}: {name}")

  # 2. Graceful error handling
  print("\n2. Graceful Error Handling:")

  # Try operations that might fail
  try:
    # Non-existent benchmark
    result = sdk.get_benchmark_result('non_existent_benchmark')
    print(f"   ✅ Non-existent benchmark handled gracefully: {result is None}")

    # Empty metrics
    metrics = sdk.get_benchmark_metrics('non_existent_benchmark')
    print(f"   ✅ Empty metrics handled gracefully: {len(metrics) == 0}")

    # Invalid build
    from ossfuzz_py.core.ossfuzz_sdk import BuildOptions
    invalid_target = {
        'name': 'invalid',
        'source_code': '',
        'project_name': 'test',
        'language': 'c++'
    }
    build_result = sdk.build_fuzz_target(invalid_target, BuildOptions())
    print(f"   ✅ Invalid build handled gracefully: {not build_result.success}")

  except Exception as e:
    print(f"   ⚠️  Error handling test failed: {e}")

  # 3. Troubleshooting tips
  print("\n3. Troubleshooting Tips:")
  print("   • Check component availability before using features")
  print("   • Verify configuration and environment variables")
  print("   • Use DEBUG log level for detailed information")
  print("   • Check file permissions for work directories")
  print("   • Ensure required dependencies are installed")


def main():
  """Main function demonstrating simple benchmark operations."""
  print("🎯 OSS-Fuzz SDK Simple Benchmark Example")
  print("=" * 50)

  # Initialize SDK
  print("\n📋 Initializing SDK")
  try:
    from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK, SDKConfig

    # Use a simple configuration
    config = SDKConfig(storage_backend='local',
                       storage_path=tempfile.mkdtemp(prefix='ossfuzz_demo_'),
                       log_level='INFO')

    sdk = OSSFuzzSDK('sample_project', config)
    print("✅ SDK initialized for project: sample_project")
    print(f"   Storage path: {config.storage_path}")

  except Exception as e:
    print(f"❌ Failed to initialize SDK: {e}")
    return False

  # Create sample fuzz target
  target_spec = create_sample_fuzz_target()

  # Demonstrate operations
  build_result = demonstrate_build_operations(sdk, target_spec)
  run_result = demonstrate_run_operations(sdk, target_spec, build_result)
  benchmark_id = demonstrate_benchmark_operations(sdk)
  demonstrate_result_analysis(sdk, benchmark_id)
  demonstrate_error_handling(sdk)

  # Summary
  print("\n🎉 Simple Benchmark Example Summary")
  print("=" * 40)
  print("✅ Operations demonstrated:")
  print("   • Sample fuzz target creation")
  print("   • Build operations with options")
  print("   • Run operations with configuration")
  print("   • Benchmark management")
  print("   • Result analysis and metrics")
  print("   • Error handling and troubleshooting")

  print("\n📋 Key learnings:")
  print("   • SDK handles missing components gracefully")
  print("   • Configuration affects all operations")
  print("   • Results provide detailed information")
  print("   • Error handling is built-in")

  print("\n🚀 Next steps:")
  print("   • Try intermediate/01_build_operations.py for advanced builds")
  print("   • Explore intermediate/04_pipeline_automation.py for workflows")
  print("   • Check advanced examples for production use cases")

  return True


if __name__ == '__main__':
  try:
    success = main()
    if success:
      print("\n🎯 Simple benchmark example completed successfully!")
      sys.exit(0)
    else:
      print("\n❌ Simple benchmark example failed.")
      sys.exit(1)

  except KeyboardInterrupt:
    print("\n\n⏹️  Example interrupted by user.")
    sys.exit(1)
  except Exception as e:
    print(f"\n❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
