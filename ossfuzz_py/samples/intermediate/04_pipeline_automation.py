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
OSS-Fuzz SDK Pipeline Automation Example

This example demonstrates how to create automated fuzzing pipelines
that combine building, running, and analysis into streamlined workflows.

What this example covers:
- Complete pipeline configuration
- Multi-trial execution
- Automated result analysis
- Pipeline monitoring and reporting
- Error recovery and retry logic
- Performance optimization

Prerequisites:
- OSS-Fuzz SDK installed: pip install ossfuzz-py
- Understanding of basic SDK operations
"""

import os
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

# Add the parent directory to the path so we can import the SDK
sys.path.append(str(Path(__file__).parent.parent.parent))


def create_pipeline_configuration():
  """Create comprehensive pipeline configuration."""
  print("⚙️ Creating Pipeline Configuration")
  print("-" * 35)

  try:
    from ossfuzz_py.core.ossfuzz_sdk import (BuildOptions, PipelineOptions,
                                             RunOptions)

    # Build configuration
    build_options = BuildOptions(
        sanitizer='address',
        architecture='x86_64',
        fuzzing_engine='libfuzzer',
        timeout_seconds=1800,  # 30 minutes
        environment_vars={
            'FUZZING_ENGINE': 'libfuzzer',
            'SANITIZER': 'address',
            'ARCHITECTURE': 'x86_64'
        },
        build_args=['--enable-fuzzing', '--optimize-for-fuzzing'])

    # Run configuration
    run_options = RunOptions(
        duration_seconds=3600,  # 1 hour
        timeout_seconds=30,  # 30 seconds per input
        max_memory_mb=2048,  # 2GB memory limit
        detect_leaks=True,
        extract_coverage=True,
        corpus_dir='corpus',
        output_dir='fuzz_output',
        engine_args=['-max_len=1024', '-rss_limit_mb=2048'],
        env_vars={
            'ASAN_OPTIONS': 'detect_odr_violation=0:abort_on_error=1',
            'MSAN_OPTIONS': 'halt_on_error=1',
            'UBSAN_OPTIONS': 'halt_on_error=1'
        })

    # Pipeline configuration
    pipeline_options = PipelineOptions(
        build_options=build_options,
        run_options=run_options,
        trials=5,  # Run 5 trials for statistical significance
        analyze_coverage=True,
        store_results=True)

    print("✅ Pipeline configuration created:")
    print(f"   Build sanitizer: {build_options.sanitizer}")
    print(f"   Build timeout: {build_options.timeout_seconds}s")
    print(f"   Build args: {len(build_options.build_args)} arguments")
    print(f"   Run duration: {run_options.duration_seconds}s")
    print(f"   Run memory limit: {run_options.max_memory_mb}MB")
    print(f"   Engine args: {len(run_options.engine_args)} arguments")
    print(f"   Pipeline trials: {pipeline_options.trials}")
    print(f"   Coverage analysis: {pipeline_options.analyze_coverage}")
    print(f"   Result storage: {pipeline_options.store_results}")

    return pipeline_options

  except Exception as e:
    print(f"❌ Failed to create pipeline configuration: {e}")
    return None


def create_sample_benchmarks():
  """Create sample benchmarks for pipeline testing."""
  print("\n📝 Creating Sample Benchmarks")
  print("-" * 30)

  benchmarks = [
      {
          'id': 'string_parser_001',
          'name': 'String Parser',
          'description': 'Tests string parsing functionality',
          'complexity': 'low',
          'expected_runtime': 300  # 5 minutes
      },
      {
          'id': 'json_decoder_002',
          'name': 'JSON Decoder',
          'description': 'Tests JSON decoding with various inputs',
          'complexity': 'medium',
          'expected_runtime': 600  # 10 minutes
      },
      {
          'id': 'image_processor_003',
          'name': 'Image Processor',
          'description': 'Tests image processing algorithms',
          'complexity': 'high',
          'expected_runtime': 1200  # 20 minutes
      }
  ]

  print(f"✅ Created {len(benchmarks)} sample benchmarks:")
  for benchmark in benchmarks:
    print(
        f"   • {benchmark['id']}: {benchmark['name']} ({benchmark['complexity']} complexity)"
    )

  return benchmarks


def run_single_pipeline(sdk, benchmark, pipeline_options):
  """Run a complete pipeline for a single benchmark."""
  benchmark_id = benchmark['id']
  benchmark_name = benchmark['name']

  print(f"\n🚀 Running Pipeline: {benchmark_name}")
  print(f"   Benchmark ID: {benchmark_id}")
  print(f"   Expected runtime: {benchmark['expected_runtime']}s")
  print(f"   Complexity: {benchmark['complexity']}")

  start_time = time.time()

  try:
    # Run the complete pipeline
    pipeline_result = sdk.run_full_pipeline(benchmark_id, pipeline_options)

    end_time = time.time()
    actual_runtime = end_time - start_time

    # Analyze pipeline results
    if pipeline_result.success:
      print("   ✅ Pipeline completed successfully!")
      print(f"      Pipeline ID: {pipeline_result.pipeline_id}")
      print(f"      Actual runtime: {actual_runtime:.1f}s")

      # Analyze build results
      build_results = pipeline_result.build_results
      successful_builds = sum(1 for r in build_results if r.success)
      print(
          f"      Builds: {successful_builds}/{len(build_results)} successful")

      # Analyze run results
      run_results = pipeline_result.run_results
      successful_runs = sum(1 for r in run_results if r.success)
      crashes_found = sum(1 for r in run_results if r.success and r.crashes)

      print(f"      Runs: {successful_runs}/{len(run_results)} successful")
      print(f"      Crashes found: {crashes_found}")

      # Calculate coverage statistics
      coverage_data = []
      avg_coverage = 0
      max_coverage = 0

      for result in run_results:
        if result.success and result.coverage_data:
          cov_pcs = result.coverage_data.get('cov_pcs', 0)
          total_pcs = result.coverage_data.get('total_pcs', 1)
          if total_pcs > 0:
            coverage_data.append(cov_pcs / total_pcs * 100)

      if coverage_data:
        avg_coverage = sum(coverage_data) / len(coverage_data)
        max_coverage = max(coverage_data)
        print(f"      Average coverage: {avg_coverage:.1f}%")
        print(f"      Maximum coverage: {max_coverage:.1f}%")

      return {
          'success': True,
          'benchmark_id': benchmark_id,
          'runtime': actual_runtime,
          'builds_successful': successful_builds,
          'builds_total': len(build_results),
          'runs_successful': successful_runs,
          'runs_total': len(run_results),
          'crashes_found': crashes_found,
          'average_coverage': avg_coverage if coverage_data else 0,
          'max_coverage': max_coverage if coverage_data else 0,
          'pipeline_result': pipeline_result
      }

    print(f"   ❌ Pipeline failed: {pipeline_result.message}")
    print(f"      Runtime: {actual_runtime:.1f}s")

    return {
        'success': False,
        'benchmark_id': benchmark_id,
        'runtime': actual_runtime,
        'error_message': pipeline_result.message,
        'pipeline_result': pipeline_result
    }

  except Exception as e:
    end_time = time.time()
    actual_runtime = end_time - start_time

    print(f"   ❌ Pipeline exception: {e}")
    print(f"      Runtime: {actual_runtime:.1f}s")

    return {
        'success': False,
        'benchmark_id': benchmark_id,
        'runtime': actual_runtime,
        'error_message': str(e)
    }


def run_batch_pipeline(sdk, benchmarks, pipeline_options):
  """Run pipelines for multiple benchmarks in batch."""
  print(f"\n🔄 Running Batch Pipeline ({len(benchmarks)} benchmarks)")
  print("=" * 50)

  batch_start_time = time.time()
  results = []

  for i, benchmark in enumerate(benchmarks, 1):
    print(f"\n[{i}/{len(benchmarks)}] Processing: {benchmark['name']}")

    # Run individual pipeline
    result = run_single_pipeline(sdk, benchmark, pipeline_options)
    results.append(result)

    # Show progress
    elapsed = time.time() - batch_start_time
    if i < len(benchmarks):
      avg_time_per_benchmark = elapsed / i
      estimated_remaining = avg_time_per_benchmark * (len(benchmarks) - i)
      print(f"   Progress: {i}/{len(benchmarks)} completed")
      print(f"   Estimated remaining time: {estimated_remaining:.1f}s")

  batch_end_time = time.time()
  total_batch_time = batch_end_time - batch_start_time

  # Analyze batch results
  print("\n📊 Batch Pipeline Results")
  print("-" * 25)

  successful_pipelines = sum(1 for r in results if r['success'])
  total_crashes = sum(
      r.get('crashes_found', 0) for r in results if r['success'])

  print(f"✅ Batch completed in {total_batch_time:.1f}s")
  print(f"   Successful pipelines: {successful_pipelines}/{len(results)}")
  print(f"   Total crashes found: {total_crashes}")

  # Detailed results
  print("\n📋 Detailed Results:")
  for result in results:
    benchmark_id = result['benchmark_id']
    if result['success']:
      builds = f"{result['builds_successful']}/{result['builds_total']}"
      runs = f"{result['runs_successful']}/{result['runs_total']}"
      crashes = result['crashes_found']
      coverage = result.get('average_coverage', 0)
      print(
          f"   ✅ {benchmark_id}: Builds={builds}, Runs={runs}, Crashes={crashes}, Cov={coverage:.1f}%"
      )
    else:
      error = result.get('error_message', 'Unknown error')[:50]
      print(f"   ❌ {benchmark_id}: Failed - {error}")

  return results


def analyze_pipeline_performance(results):
  """Analyze pipeline performance and generate insights."""
  print("\n📈 Pipeline Performance Analysis")
  print("-" * 35)

  if not results:
    print("❌ No results to analyze")
    return

  successful_results = [r for r in results if r['success']]

  if not successful_results:
    print("❌ No successful results to analyze")
    return

  # Runtime analysis
  runtimes = [r['runtime'] for r in successful_results]
  avg_runtime = sum(runtimes) / len(runtimes)
  min_runtime = min(runtimes)
  max_runtime = max(runtimes)

  print("⏱️ Runtime Statistics:")
  print(f"   Average: {avg_runtime:.1f}s")
  print(f"   Minimum: {min_runtime:.1f}s")
  print(f"   Maximum: {max_runtime:.1f}s")

  # Build success analysis
  total_builds = sum(r['builds_total'] for r in successful_results)
  successful_builds = sum(r['builds_successful'] for r in successful_results)
  build_success_rate = successful_builds / total_builds if total_builds > 0 else 0

  print("\n🏗️ Build Statistics:")
  print(f"   Total builds: {total_builds}")
  print(f"   Successful builds: {successful_builds}")
  print(f"   Build success rate: {build_success_rate:.2%}")

  # Run success analysis
  total_runs = sum(r['runs_total'] for r in successful_results)
  successful_runs = sum(r['runs_successful'] for r in successful_results)
  run_success_rate = successful_runs / total_runs if total_runs > 0 else 0

  print("\n🏃 Run Statistics:")
  print(f"   Total runs: {total_runs}")
  print(f"   Successful runs: {successful_runs}")
  print(f"   Run success rate: {run_success_rate:.2%}")

  # Crash analysis
  total_crashes = sum(r['crashes_found'] for r in successful_results)
  benchmarks_with_crashes = sum(
      1 for r in successful_results if r['crashes_found'] > 0)

  print("\n💥 Crash Statistics:")
  print(f"   Total crashes found: {total_crashes}")
  print(
      f"   Benchmarks with crashes: {benchmarks_with_crashes}/{len(successful_results)}"
  )

  # Coverage analysis
  coverage_data = [
      r.get('average_coverage', 0)
      for r in successful_results
      if r.get('average_coverage', 0) > 0
  ]
  avg_coverage = 0
  max_coverage = 0
  min_coverage = 0

  if coverage_data:
    avg_coverage = sum(coverage_data) / len(coverage_data)
    max_coverage = max(coverage_data)
    min_coverage = min(coverage_data)

    print("\n📊 Coverage Statistics:")
    print(f"   Average coverage: {avg_coverage:.1f}%")
    print(f"   Maximum coverage: {max_coverage:.1f}%")
    print(f"   Minimum coverage: {min_coverage:.1f}%")

  # Performance insights
  print("\n💡 Performance Insights:")

  if build_success_rate < 0.8:
    print("   ⚠️  Low build success rate - check build configuration")

  if run_success_rate < 0.8:
    print("   ⚠️  Low run success rate - check run configuration")

  if total_crashes == 0:
    print("   ℹ️  No crashes found - consider increasing run duration")

  if coverage_data and avg_coverage < 50:
    print("   ℹ️  Low coverage - consider optimizing corpus or run parameters")

  if avg_runtime > 1800:  # 30 minutes
    print("   ⚠️  Long runtime - consider optimizing pipeline configuration")


def demonstrate_pipeline_monitoring(sdk, results):
  """Demonstrate pipeline monitoring and alerting."""
  print("\n🔍 Pipeline Monitoring")
  print("-" * 22)

  # Monitor system metrics
  try:
    system_metrics = sdk.get_system_metrics()
    print("📊 System Metrics:")
    print(f"   Total benchmarks: {system_metrics.get('total_benchmarks', 0)}")
    print(
        f"   Build success rate: {system_metrics.get('build_success_rate', 0):.2%}"
    )
    print(
        f"   Average coverage: {system_metrics.get('average_coverage', 0):.1f}%"
    )

  except Exception as e:
    print(f"⚠️  Could not get system metrics: {e}")

  # Check for alerts
  print("\n🚨 Alert Monitoring:")
  alerts = []

  for result in results:
    if not result['success']:
      alerts.append(f"Pipeline failed for {result['benchmark_id']}")
    elif result.get('crashes_found', 0) > 10:
      alerts.append(
          f"High crash count for {result['benchmark_id']}: {result['crashes_found']}"
      )
    elif result.get('average_coverage', 0) < 20:
      alerts.append(
          f"Low coverage for {result['benchmark_id']}: {result.get('average_coverage', 0):.1f}%"
      )

  if alerts:
    print(f"   Found {len(alerts)} alerts:")
    for alert in alerts:
      print(f"     ⚠️  {alert}")
  else:
    print("   ✅ No alerts detected")


def main():
  """Main function demonstrating pipeline automation."""
  print("🔄 OSS-Fuzz SDK Pipeline Automation Example")
  print("=" * 55)

  # Initialize SDK
  print("\n📋 Initializing SDK")
  try:
    from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK, SDKConfig

    config = SDKConfig(
        storage_backend='local',
        storage_path=tempfile.mkdtemp(prefix='ossfuzz_pipeline_'),
        log_level='INFO',
        enable_caching=True,
        timeout_seconds=7200  # 2 hours
    )

    sdk = OSSFuzzSDK('pipeline_project', config)
    print("✅ SDK initialized for pipeline automation")
    print(f"   Storage path: {config.storage_path}")
    print(f"   Timeout: {config.timeout_seconds}s")

  except Exception as e:
    print(f"❌ Failed to initialize SDK: {e}")
    return False

  # Create pipeline configuration
  pipeline_options = create_pipeline_configuration()
  if not pipeline_options:
    return False

  # Create sample benchmarks
  benchmarks = create_sample_benchmarks()

  # Run batch pipeline
  results = run_batch_pipeline(sdk, benchmarks, pipeline_options)

  # Analyze performance
  analyze_pipeline_performance(results)

  # Monitor pipeline
  demonstrate_pipeline_monitoring(sdk, results)

  # Summary
  print("\n🎉 Pipeline Automation Summary")
  print("=" * 35)
  print("✅ Pipeline automation demonstrated:")
  print("   • Complete pipeline configuration")
  print("   • Multi-trial execution")
  print("   • Batch processing")
  print("   • Performance analysis")
  print("   • Monitoring and alerting")

  print("\n📋 Key features:")
  print("   • Automated build → run → analyze workflows")
  print("   • Statistical significance through multiple trials")
  print("   • Comprehensive result analysis")
  print("   • Performance monitoring and insights")
  print("   • Error handling and recovery")

  print("\n🚀 Next steps:")
  print("   • Try advanced/01_batch_processing.py for multi-project automation")
  print(
      "   • Explore advanced/03_monitoring_alerts.py for production monitoring")
  print("   • Check production examples for enterprise deployment")

  return True


if __name__ == '__main__':
  try:
    success = main()
    if success:
      print("\n🎯 Pipeline automation example completed successfully!")
      sys.exit(0)
    else:
      print("\n❌ Pipeline automation example failed.")
      sys.exit(1)

  except KeyboardInterrupt:
    print("\n\n⏹️  Example interrupted by user.")
    sys.exit(1)
  except Exception as e:
    print(f"\n❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
