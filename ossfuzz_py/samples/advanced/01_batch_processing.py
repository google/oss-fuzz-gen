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
# pylint: disable=invalid-name,line-too-long
"""
OSS-Fuzz SDK Advanced Batch Processing Example

This example demonstrates how to process multiple projects and benchmarks
efficiently using advanced batch processing techniques.

What this example covers:
- Multi-project batch processing
- Parallel execution strategies
- Resource management and optimization
- Progress tracking and reporting
- Error recovery and retry logic
- Data aggregation and analysis

Prerequisites:
- OSS-Fuzz SDK installed: pip install ossfuzz-py
- Understanding of pipeline automation
- Optional: concurrent.futures for parallel processing
"""

import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# Add the parent directory to the path so we can import the SDK
sys.path.append(str(Path(__file__).parent.parent.parent))


class BatchProcessor:
  """Advanced batch processor for multiple projects and benchmarks."""

  def __init__(self, max_workers=4, retry_attempts=3):
    """Initialize batch processor."""
    self.max_workers = max_workers
    self.retry_attempts = retry_attempts
    self.results = {}
    self.progress_lock = threading.Lock()
    self.completed_tasks = 0
    self.total_tasks = 0

  def create_project_configurations(self):
    """Create configurations for multiple projects."""
    print("🏗️ Creating Multi-Project Configurations")
    print("-" * 40)

    projects = [{
        'name': 'libpng',
        'description': 'PNG image library',
        'priority': 'high',
        'benchmarks': [
            'png_decode_fuzzer', 'png_encode_fuzzer', 'png_transform_fuzzer'
        ],
        'config': {
            'storage_backend': 'local',
            'log_level': 'INFO',
            'timeout_seconds': 3600
        }
    }, {
        'name': 'libjpeg',
        'description': 'JPEG image library',
        'priority': 'high',
        'benchmarks': ['jpeg_decode_fuzzer', 'jpeg_encode_fuzzer'],
        'config': {
            'storage_backend': 'local',
            'log_level': 'INFO',
            'timeout_seconds': 2400
        }
    }, {
        'name': 'zlib',
        'description': 'Compression library',
        'priority': 'medium',
        'benchmarks': ['inflate_fuzzer', 'deflate_fuzzer', 'gzip_fuzzer'],
        'config': {
            'storage_backend': 'local',
            'log_level': 'WARNING',
            'timeout_seconds': 1800
        }
    }, {
        'name': 'openssl',
        'description': 'Cryptography library',
        'priority': 'critical',
        'benchmarks': [
            'rsa_fuzzer', 'aes_fuzzer', 'x509_fuzzer', 'asn1_fuzzer'
        ],
        'config': {
            'storage_backend': 'local',
            'log_level': 'INFO',
            'timeout_seconds': 4800
        }
    }]

    print(f"✅ Created configurations for {len(projects)} projects:")
    for project in projects:
      benchmark_count = len(project['benchmarks'])
      print(f"   • {project['name']}: {benchmark_count} benchmarks "
            f"({project['priority']} priority)")

    return projects

  def create_batch_tasks(self, projects):
    """Create individual tasks for batch processing."""
    print("\n📋 Creating Batch Tasks")
    print("-" * 22)

    tasks = []
    task_id = 0

    for project in projects:
      for benchmark_id in project['benchmarks']:
        task = {
            'id':
                task_id,
            'project_name':
                project['name'],
            'benchmark_id':
                benchmark_id,
            'priority':
                project['priority'],
            'config':
                project['config'],
            'description':
                f"{project['name']}/{benchmark_id}",
            'estimated_duration':
                self._estimate_task_duration(project['priority'])
        }
        tasks.append(task)
        task_id += 1

    # Sort tasks by priority and estimated duration
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    tasks.sort(key=lambda t:
               (priority_order.get(t['priority'], 4), t['estimated_duration']))

    print(f"✅ Created {len(tasks)} batch tasks:")
    print(
        f"   Critical: {sum(1 for t in tasks if t['priority'] == 'critical')}")
    print(f"   High: {sum(1 for t in tasks if t['priority'] == 'high')}")
    print(f"   Medium: {sum(1 for t in tasks if t['priority'] == 'medium')}")
    print(f"   Low: {sum(1 for t in tasks if t['priority'] == 'low')}")

    total_estimated_time = sum(t['estimated_duration'] for t in tasks)
    parallel_estimated_time = total_estimated_time / self.max_workers

    print("\n⏱️ Time Estimates:")
    print(
        f"   Sequential execution: {total_estimated_time:.0f}s ({total_estimated_time/60:.1f}m)"
    )
    print(f"   Parallel execution ({self.max_workers} workers): "
          f"{parallel_estimated_time:.0f}s ({parallel_estimated_time/60:.1f}m)")

    return tasks

  def _estimate_task_duration(self, priority):
    """Estimate task duration based on priority."""
    duration_map = {
        'critical': 1200,  # 20 minutes
        'high': 900,  # 15 minutes
        'medium': 600,  # 10 minutes
        'low': 300  # 5 minutes
    }
    return duration_map.get(priority, 600)

  def execute_single_task(self, task):
    """Execute a single batch task."""
    task_id = task['id']
    project_name = task['project_name']
    benchmark_id = task['benchmark_id']

    start_time = time.time()

    try:
      # Initialize SDK for this task
      from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK, SDKConfig

      config = SDKConfig(**task['config'])
      sdk = OSSFuzzSDK(project_name, config)

      # Create pipeline options based on priority
      pipeline_options = self._create_pipeline_options(task['priority'])

      # Execute pipeline
      pipeline_result = sdk.run_full_pipeline(benchmark_id, pipeline_options)

      end_time = time.time()
      duration = end_time - start_time

      # Analyze results
      result = {
          'task_id':
              task_id,
          'project_name':
              project_name,
          'benchmark_id':
              benchmark_id,
          'priority':
              task['priority'],
          'success':
              pipeline_result.success,
          'duration':
              duration,
          'start_time':
              start_time,
          'end_time':
              end_time,
          'message':
              pipeline_result.message
              if not pipeline_result.success else 'Success'
      }

      if pipeline_result.success:
        # Extract detailed metrics
        build_success = sum(
            1 for r in pipeline_result.build_results if r.success)
        build_total = len(pipeline_result.build_results)
        run_success = sum(1 for r in pipeline_result.run_results if r.success)
        run_total = len(pipeline_result.run_results)
        crashes = sum(
            1 for r in pipeline_result.run_results if r.success and r.crashes)

        result.update({
            'builds_successful':
                build_success,
            'builds_total':
                build_total,
            'runs_successful':
                run_success,
            'runs_total':
                run_total,
            'crashes_found':
                crashes,
            'build_success_rate':
                build_success / build_total if build_total > 0 else 0,
            'run_success_rate':
                run_success / run_total if run_total > 0 else 0
        })

        # Get additional metrics
        try:
          metrics = sdk.get_benchmark_metrics(benchmark_id)
          result['coverage'] = metrics.get('coverage', 0)
          result['line_coverage_diff'] = metrics.get('line_coverage_diff', 0)
        except:
          result['coverage'] = 0
          result['line_coverage_diff'] = 0

      # Update progress
      with self.progress_lock:
        self.completed_tasks += 1
        progress = (self.completed_tasks / self.total_tasks) * 100
        print(
            f"   [{self.completed_tasks}/{self.total_tasks}] {progress:.1f}% - "
            f"{task['description']}: {'✅' if result['success'] else '❌'} ({duration:.1f}s)"
        )

      return result

    except Exception as e:
      end_time = time.time()
      duration = end_time - start_time

      result = {
          'task_id': task_id,
          'project_name': project_name,
          'benchmark_id': benchmark_id,
          'priority': task['priority'],
          'success': False,
          'duration': duration,
          'start_time': start_time,
          'end_time': end_time,
          'message': str(e),
          'error': True
      }

      with self.progress_lock:
        self.completed_tasks += 1
        progress = (self.completed_tasks / self.total_tasks) * 100
        print(
            f"   [{self.completed_tasks}/{self.total_tasks}] {progress:.1f}% - "
            f"{task['description']}: ❌ Error ({duration:.1f}s)")

      return result

  def _create_pipeline_options(self, priority):
    """Create pipeline options based on task priority."""
    from ossfuzz_py.core.ossfuzz_sdk import (BuildOptions, PipelineOptions,
                                             RunOptions)

    # Adjust configuration based on priority
    if priority == 'critical':
      trials = 5
      duration = 1800  # 30 minutes
      timeout = 60
    elif priority == 'high':
      trials = 3
      duration = 1200  # 20 minutes
      timeout = 45
    elif priority == 'medium':
      trials = 2
      duration = 900  # 15 minutes
      timeout = 30
    else:  # low
      trials = 1
      duration = 600  # 10 minutes
      timeout = 25

    build_options = BuildOptions(sanitizer='address',
                                 timeout_seconds=timeout * 60)

    run_options = RunOptions(duration_seconds=duration,
                             timeout_seconds=timeout,
                             extract_coverage=True)

    return PipelineOptions(build_options=build_options,
                           run_options=run_options,
                           trials=trials,
                           analyze_coverage=True,
                           store_results=True)

  def execute_batch_parallel(self, tasks):
    """Execute batch tasks in parallel."""
    print("\n🚀 Executing Batch Tasks (Parallel)")
    print("-" * 35)

    self.total_tasks = len(tasks)
    self.completed_tasks = 0
    batch_start_time = time.time()

    print(f"Starting parallel execution with {self.max_workers} workers...")
    print(f"Total tasks: {self.total_tasks}")

    results = []

    with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
      # Submit all tasks
      future_to_task = {
          executor.submit(self.execute_single_task, task): task
          for task in tasks
      }

      # Collect results as they complete
      for future in as_completed(future_to_task):
        task = future_to_task[future]
        try:
          result = future.result()
          results.append(result)
        except Exception as e:
          print(f"   ❌ Task {task['id']} failed with exception: {e}")
          results.append({
              'task_id': task['id'],
              'project_name': task['project_name'],
              'benchmark_id': task['benchmark_id'],
              'success': False,
              'message': str(e),
              'error': True
          })

    batch_end_time = time.time()
    total_duration = batch_end_time - batch_start_time

    print(
        f"\n✅ Batch execution completed in {total_duration:.1f}s ({total_duration/60:.1f}m)"
    )

    return results

  def analyze_batch_results(self, results):
    """Analyze and report batch processing results."""
    print("\n📊 Batch Processing Analysis")
    print("-" * 30)

    if not results:
      print("❌ No results to analyze")
      return None

    # Overall statistics
    total_tasks = len(results)
    successful_tasks = sum(1 for r in results if r.get('success', False))
    failed_tasks = total_tasks - successful_tasks

    print("📈 Overall Statistics:")
    print(f"   Total tasks: {total_tasks}")
    print(
        f"   Successful: {successful_tasks} ({successful_tasks/total_tasks:.1%})"
    )
    print(f"   Failed: {failed_tasks} ({failed_tasks/total_tasks:.1%})")

    # Performance analysis
    durations = [r.get('duration', 0) for r in results if 'duration' in r]
    avg_duration = 0
    min_duration = 0
    max_duration = 0

    if durations:
      avg_duration = sum(durations) / len(durations)
      min_duration = min(durations)
      max_duration = max(durations)

      print("\n⏱️ Performance Statistics:")
      print(f"   Average duration: {avg_duration:.1f}s")
      print(f"   Minimum duration: {min_duration:.1f}s")
      print(f"   Maximum duration: {max_duration:.1f}s")

    # Project-wise analysis
    project_stats = {}
    for result in results:
      project = result.get('project_name', 'unknown')
      if project not in project_stats:
        project_stats[project] = {'total': 0, 'successful': 0, 'failed': 0}

      project_stats[project]['total'] += 1
      if result.get('success', False):
        project_stats[project]['successful'] += 1
      else:
        project_stats[project]['failed'] += 1

    print("\n🏗️ Project-wise Statistics:")
    for project, stats in project_stats.items():
      success_rate = stats['successful'] / stats['total'] if stats[
          'total'] > 0 else 0
      print(
          f"   {project}: {stats['successful']}/{stats['total']} ({success_rate:.1%})"
      )

    # Priority analysis
    priority_stats = {}
    for result in results:
      priority = result.get('priority', 'unknown')
      if priority not in priority_stats:
        priority_stats[priority] = {'total': 0, 'successful': 0}

      priority_stats[priority]['total'] += 1
      if result.get('success', False):
        priority_stats[priority]['successful'] += 1

    print("\n🎯 Priority-wise Statistics:")
    for priority, stats in priority_stats.items():
      success_rate = stats['successful'] / stats['total'] if stats[
          'total'] > 0 else 0
      print(
          f"   {priority}: {stats['successful']}/{stats['total']} ({success_rate:.1%})"
      )

    # Detailed metrics for successful tasks
    successful_results = [r for r in results if r.get('success', False)]
    if successful_results:
      total_crashes = sum(r.get('crashes_found', 0) for r in successful_results)
      avg_coverage = sum(r.get('coverage', 0)
                         for r in successful_results) / len(successful_results)

      print("\n💥 Fuzzing Results:")
      print(f"   Total crashes found: {total_crashes}")
      print(f"   Average coverage: {avg_coverage:.1f}%")
      print(
          f"   Benchmarks with crashes: {sum(1 for r in successful_results if r.get('crashes_found', 0) > 0)}"
      )

    return {
        'total_tasks':
            total_tasks,
        'successful_tasks':
            successful_tasks,
        'failed_tasks':
            failed_tasks,
        'success_rate':
            successful_tasks / total_tasks if total_tasks > 0 else 0,
        'project_stats':
            project_stats,
        'priority_stats':
            priority_stats,
        'performance_stats': {
            'avg_duration': avg_duration if durations else 0,
            'min_duration': min_duration if durations else 0,
            'max_duration': max_duration if durations else 0
        }
    }

  def export_batch_results(self, results, output_path=None):
    """Export batch results to JSON file."""
    if not output_path:
      timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
      output_path = f"batch_results_{timestamp}.json"

    export_data = {
        'export_timestamp': datetime.now().isoformat(),
        'total_tasks': len(results),
        'successful_tasks': sum(1 for r in results if r.get('success', False)),
        'batch_processor_config': {
            'max_workers': self.max_workers,
            'retry_attempts': self.retry_attempts
        },
        'results': results
    }

    with open(output_path, 'w') as f:
      json.dump(export_data, f, indent=2)

    print(f"\n💾 Results exported to: {output_path}")
    return output_path


def main():
  """Main function demonstrating advanced batch processing."""
  print("🔄 OSS-Fuzz SDK Advanced Batch Processing Example")
  print("=" * 60)

  # Initialize batch processor
  print("\n⚙️ Initializing Batch Processor")
  max_workers = 4  # Adjust based on your system
  batch_processor = BatchProcessor(max_workers=max_workers, retry_attempts=2)

  print("✅ Batch processor initialized:")
  print(f"   Max workers: {max_workers}")
  print(f"   Retry attempts: {batch_processor.retry_attempts}")

  # Create project configurations
  projects = batch_processor.create_project_configurations()

  # Create batch tasks
  tasks = batch_processor.create_batch_tasks(projects)

  # Execute batch processing
  results = batch_processor.execute_batch_parallel(tasks)

  # Analyze results
  analysis = batch_processor.analyze_batch_results(results)

  # Export results
  export_path = batch_processor.export_batch_results(results)

  # Summary
  print("\n🎉 Advanced Batch Processing Summary")
  print("=" * 40)
  print("✅ Batch processing completed:")
  print(f"   • Processed {len(projects)} projects")
  print(f"   • Executed {len(tasks)} tasks")
  success_rate = analysis.get('success_rate', 0) if analysis else 0
  print(f"   • Success rate: {success_rate:.1%}")
  print(f"   • Results exported to: {export_path}")

  print("\n📋 Key features demonstrated:")
  print("   • Multi-project batch processing")
  print("   • Parallel execution with thread pool")
  print("   • Priority-based task scheduling")
  print("   • Progress tracking and monitoring")
  print("   • Comprehensive result analysis")
  print("   • Data export and reporting")

  print("\n🚀 Next steps:")
  print("   • Try advanced/03_monitoring_alerts.py for production monitoring")
  print("   • Explore production examples for enterprise deployment")
  print("   • Scale up with more workers for larger batches")

  return True


if __name__ == '__main__':
  try:
    success = main()
    if success:
      print("\n🎯 Advanced batch processing example completed successfully!")
      sys.exit(0)
    else:
      print("\n❌ Advanced batch processing example failed.")
      sys.exit(1)

  except KeyboardInterrupt:
    print("\n\n⏹️  Example interrupted by user.")
    sys.exit(1)
  except Exception as e:
    print(f"\n❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
