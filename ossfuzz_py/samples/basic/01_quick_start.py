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
# pylint: disable=invalid-name,line-too-long,unused-import
"""
OSS-Fuzz SDK Quick Start Example

This example demonstrates the most basic usage of the OSS-Fuzz SDK.
Perfect for users who want to get started quickly and see the SDK in action.

What this example covers:
- Basic SDK initialization
- Running a simple benchmark
- Getting basic metrics
- Generating a simple report

Prerequisites:
- OSS-Fuzz SDK installed: pip install ossfuzz-py
- Basic environment setup (see README.md)
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the parent directory to the path so we can import the SDK
# In a real project, you would just: from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK
sys.path.append(str(Path(__file__).parent.parent.parent))


def main():
  """Main function demonstrating basic SDK usage."""
  print("🚀 OSS-Fuzz SDK Quick Start Example")
  print("=" * 50)

  # Step 1: Basic SDK Initialization
  print("\n📋 Step 1: Initializing the SDK")

  try:
    from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK

    # Initialize with a sample project
    # In production, replace 'sample_project' with your actual project name
    project_name = 'sample_project'
    sdk = OSSFuzzSDK(project_name)

    print(f"✅ SDK initialized successfully for project: {project_name}")
    print(f"   Storage backend: {sdk.config.get('storage_backend', 'default')}")
    print(f"   Work directory: {sdk.config.get('work_dir', 'default')}")

  except ImportError as e:
    print(f"❌ Failed to import SDK: {e}")
    print(
        "   Please ensure the OSS-Fuzz SDK is installed: pip install ossfuzz-py"
    )
    return False
  except Exception as e:
    print(f"❌ Failed to initialize SDK: {e}")
    return False

  # Step 2: Check Component Availability
  print("\n🔧 Step 2: Checking Component Availability")

  components = {
      'Storage Manager': sdk.storage,
      'Result Manager': getattr(sdk, 'result_manager', None),
      'Benchmark Manager': getattr(sdk, 'benchmark_manager', None),
      'Local Builder': getattr(sdk, 'local_builder', None),
      'Local Runner': getattr(sdk, 'local_runner', None),
  }

  available_components = 0
  for name, component in components.items():
    status = "✅ Available" if component is not None else "⚠️  Not available"
    print(f"   {status}: {name}")
    if component is not None:
      available_components += 1

  print(f"\n   📊 {available_components}/{len(components)} components available")

  if available_components == 0:
    print("   ⚠️  No components available. Some features will be limited.")

  # Step 3: Try Basic Operations
  print("\n🎯 Step 3: Trying Basic Operations")

  # Try to get project summary
  try:
    summary = sdk.get_project_summary()
    print("✅ Project summary retrieved:")
    print(f"   Project: {summary.get('project_name', 'Unknown')}")
    print(f"   Last updated: {summary.get('last_updated', 'Unknown')}")
    print(f"   Total benchmarks: {summary.get('total_benchmarks', 0)}")

  except Exception as e:
    print(f"⚠️  Could not get project summary: {e}")

  # Try to list benchmarks
  try:
    benchmarks = sdk.list_benchmarks()
    print(f"✅ Found {len(benchmarks)} benchmarks")

    if benchmarks:
      print("   Sample benchmarks:")
      for i, benchmark in enumerate(benchmarks[:3]):  # Show first 3
        print(f"     {i+1}. {benchmark.get('id', 'Unknown ID')}")
    else:
      print("   No benchmarks found (this is normal for a new setup)")

  except Exception as e:
    print(f"⚠️  Could not list benchmarks: {e}")

  # Step 4: Try Running a Sample Benchmark
  print("\n🏃 Step 4: Trying to Run a Sample Benchmark")

  # Create a sample benchmark ID for demonstration
  sample_benchmark_id = 'sample_benchmark_001'

  try:
    # Try to get metrics for the sample benchmark
    metrics = sdk.get_benchmark_metrics(sample_benchmark_id)
    print(f"✅ Retrieved metrics for {sample_benchmark_id}:")

    if metrics:
      print(f"   Compiles: {metrics.get('compiles', 'Unknown')}")
      print(f"   Crashes: {metrics.get('crashes', 'Unknown')}")
      print(f"   Coverage: {metrics.get('coverage', 'Unknown')}")
    else:
      print("   No metrics available (this is normal for a new benchmark)")

  except Exception as e:
    print(f"⚠️  Could not get benchmark metrics: {e}")

  # Try to run the benchmark (this will likely fail in a demo environment)
  try:
    print(f"\n   Attempting to run benchmark: {sample_benchmark_id}")
    result = sdk.run_benchmark(sample_benchmark_id)

    if result.success:
      print("✅ Benchmark run completed successfully!")
      print(f"   Run ID: {result.run_id}")
      print(f"   Crashes detected: {result.crashes}")
      print(f"   Coverage data: {result.coverage_data}")
    else:
      print(f"⚠️  Benchmark run failed: {result.message}")
      print(
          "   This is expected in a demo environment without actual benchmarks")

  except Exception as e:
    print(f"⚠️  Could not run benchmark: {e}")
    print("   This is expected in a demo environment")

  # Step 5: Generate a Basic Report
  print("\n📊 Step 5: Generating a Basic Report")

  try:
    # Generate a project report for the last 7 days
    report = sdk.generate_project_report(days=7, include_details=False)
    print("✅ Project report generated:")
    print(f"   Project: {report.get('project_name', 'Unknown')}")
    print(
        f"   Report period: {report.get('start_date', 'Unknown')} to {report.get('end_date', 'Unknown')}"
    )

    # Show build summary if available
    build_summary = report.get('build_summary', {})
    if build_summary:
      print(f"   Total builds: {build_summary.get('total_builds', 0)}")
      print(
          f"   Build success rate: {build_summary.get('success_rate', 0):.2%}")

    # Show coverage summary if available
    coverage_summary = report.get('coverage_summary', {})
    if coverage_summary:
      print(
          f"   Average coverage: {coverage_summary.get('average_coverage', 0):.1f}%"
      )

  except Exception as e:
    print(f"⚠️  Could not generate report: {e}")

  # Step 6: Try System-Wide Metrics
  print("\n📈 Step 6: Getting System-Wide Metrics")

  try:
    system_metrics = sdk.get_system_metrics()
    print("✅ System metrics retrieved:")

    if system_metrics:
      print(f"   Total benchmarks: {system_metrics.get('total_benchmarks', 0)}")
      print(f"   Total builds: {system_metrics.get('total_builds', 0)}")
      print(
          f"   Build success rate: {system_metrics.get('build_success_rate', 0):.2%}"
      )
      print(
          f"   Average coverage: {system_metrics.get('average_coverage', 0):.1f}%"
      )
      print(f"   Total crashes: {system_metrics.get('total_crashes', 0)}")
    else:
      print("   No system metrics available (this is normal for a new setup)")

  except Exception as e:
    print(f"⚠️  Could not get system metrics: {e}")

  # Step 7: Summary and Next Steps
  print("\n🎉 Step 7: Summary and Next Steps")
  print("=" * 50)
  print("✅ Quick start example completed successfully!")
  print("\n📋 What you've learned:")
  print("   • How to initialize the OSS-Fuzz SDK")
  print("   • How to check component availability")
  print("   • How to perform basic operations")
  print("   • How to handle errors gracefully")
  print("   • How to generate reports and get metrics")

  print("\n🚀 Next steps:")
  print(
      "   1. Check out basic/02_configuration.py to learn about configuration")
  print("   2. Try basic/03_simple_benchmark.py to run a real benchmark")
  print("   3. Explore intermediate/ examples for more advanced features")
  print("   4. Read the API documentation in docs/API_DOCUMENTATION.md")

  print("\n💡 Tips:")
  print("   • Set up environment variables for better configuration")
  print("   • Install optional dependencies for full functionality:")
  print("     pip install pandas pydantic yaml chardet")
  print("   • Check the logs if you encounter issues")

  return True


if __name__ == '__main__':
  try:
    success = main()
    if success:
      print("\n🎯 Example completed successfully!")
      sys.exit(0)
    else:
      print("\n❌ Example failed. Check the output above for details.")
      sys.exit(1)

  except KeyboardInterrupt:
    print("\n\n⏹️  Example interrupted by user.")
    sys.exit(1)
  except Exception as e:
    print(f"\n❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
