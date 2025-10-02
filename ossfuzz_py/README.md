# OSS-Fuzz SDK API DOCUMENTATION

## Table of Contents

1. [Overview](#overview)
2. [Installation & Setup](#installation--setup)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Core Classes](#core-classes)
6. [Build Operations](#build-operations)
7. [Execution Operations](#execution-operations)
8. [Workflow Orchestration](#workflow-orchestration)
9. [Result Management](#result-management)
10. [Benchmark Management](#benchmark-management)
11. [Export & Analysis](#export--analysis)
12. [Historical Data Analysis](#historical-data-analysis)
13. [Error Handling](#error-handling)
14. [Examples](#examples)
15. [Best Practices](#best-practices)

## Overview

The OSS-Fuzz SDK provides a comprehensive, unified interface for building, executing, and analyzing fuzz targets and benchmarks. It integrates all aspects of the fuzzing workflow from build operations to result analysis and reporting.

### Key Features

- **Unified API**: Single entry point for all fuzzing operations
- **Flexible Configuration**: Multiple configuration options and sources
- **Robust Error Handling**: Graceful degradation and comprehensive exception management
- **Component Integration**: Seamless coordination of all SDK components
- **Comprehensive Analytics**: Built-in metrics, reporting, and analysis tools
- **Export Capabilities**: Multiple export formats for results and reports

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    OSSFuzzSDK (Main Facade)                │
├─────────────────────────────────────────────────────────────┤
│  Build Ops  │  Run Ops  │  Workflow  │  Results  │  Export │
├─────────────────────────────────────────────────────────────┤
│ ResultManager │ BenchmarkManager │ HistoryManagers │ Storage │
├─────────────────────────────────────────────────────────────┤
│        LocalBuilder/Runner │ CloudBuilder/Runner           │
└─────────────────────────────────────────────────────────────┘
```

## Installation & Setup

You can directly use the `ossfuzz-py` package from this project.

**Future Plan**: Publish to PyPI. You can install it in command line then, like `pip install ossfuzz-py`.

### Environment Variables

```bash
# Storage configuration
export OSSFUZZ_HISTORY_STORAGE_BACKEND=local
export OSSFUZZ_HISTORY_STORAGE_PATH=/path/to/data
export GCS_BUCKET_NAME=your-gcs-bucket

# Working directories
export WORK_DIR=/tmp/ossfuzz_work
export OSS_FUZZ_DIR=/path/to/oss-fuzz
```

## Quick Start

### Basic Usage

```python
from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK

# Initialize SDK
sdk = OSSFuzzSDK('my_project')

# Run a benchmark
result = sdk.run_benchmark('benchmark_id')
print(f"Success: {result.success}")

# Get metrics
metrics = sdk.get_benchmark_metrics('benchmark_id')
print(f"Build success rate: {metrics.get('build_success_rate', 0)}")

# Generate report
report = sdk.generate_project_report(days=30)
print(f"Project: {report['project_name']}")
```

### Advanced Usage

```python
from ossfuzz_py.core.ossfuzz_sdk import (
    OSSFuzzSDK, SDKConfig, PipelineOptions, BuildOptions, RunOptions
)

# Custom configuration
config = SDKConfig(
    storage_backend='gcs',
    gcs_bucket_name='my-bucket',
    log_level='DEBUG',
    enable_caching=True
)

sdk = OSSFuzzSDK('my_project', config)

# Configure pipeline options
build_opts = BuildOptions(
    sanitizer='memory',
    architecture='x86_64',
    timeout_seconds=1800
)

run_opts = RunOptions(
    duration_seconds=3600,
    detect_leaks=True,
    extract_coverage=True
)

pipeline_opts = PipelineOptions(
    build_options=build_opts,
    run_options=run_opts,
    trials=3,
    analyze_coverage=True
)

# Run full pipeline
result = sdk.run_full_pipeline('benchmark_id', pipeline_opts)
print(f"Pipeline success: {result.success}")
print(f"Successful builds: {sum(1 for r in result.build_results if r.success)}")
print(f"Successful runs: {sum(1 for r in result.run_results if r.success)}")
```

## Configuration

### SDKConfig Class

The `SDKConfig` class provides centralized configuration management.

```python
class SDKConfig:
    def __init__(self,
                 storage_backend: str = 'local',
                 storage_path: Optional[str] = None,
                 gcs_bucket_name: Optional[str] = None,
                 work_dir: Optional[str] = None,
                 oss_fuzz_dir: Optional[str] = None,
                 enable_caching: bool = True,
                 log_level: str = 'INFO',
                 timeout_seconds: int = 3600,
                 max_retries: int = 3)
```

#### Parameters

- **storage_backend** (`str`): Storage backend type ('local', 'gcs')
- **storage_path** (`str`, optional): Local storage path
- **gcs_bucket_name** (`str`, optional): GCS bucket name for cloud storage
- **work_dir** (`str`, optional): Working directory for operations
- **oss_fuzz_dir** (`str`, optional): OSS-Fuzz repository directory
- **enable_caching** (`bool`): Enable result caching
- **log_level** (`str`): Logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR')
- **timeout_seconds** (`int`): Default timeout for operations
- **max_retries** (`int`): Maximum retry attempts for failed operations

#### Methods

- **`to_dict()`**: Convert configuration to dictionary

### Options Classes

#### BuildOptions

Configuration for build operations.

```python
class BuildOptions:
    def __init__(self,
                 sanitizer: Optional[str] = 'address',
                 architecture: str = 'x86_64',
                 fuzzing_engine: Optional[str] = 'libfuzzer',
                 environment_vars: Optional[Dict[str, str]] = None,
                 build_args: Optional[List[str]] = None,
                 timeout_seconds: Optional[int] = None)
```

#### RunOptions

Configuration for execution operations.

```python
class RunOptions:
    def __init__(self,
                 duration_seconds: int = 3600,
                 timeout_seconds: int = 25,
                 max_memory_mb: int = 1024,
                 detect_leaks: bool = True,
                 extract_coverage: bool = False,
                 corpus_dir: Optional[str] = None,
                 output_dir: str = 'fuzz_output',
                 engine_args: Optional[List[str]] = None,
                 env_vars: Optional[Dict[str, str]] = None)
```

#### PipelineOptions

Configuration for full pipeline operations.

```python
class PipelineOptions:
    def __init__(self,
                 build_options: Optional[BuildOptions] = None,
                 run_options: Optional[RunOptions] = None,
                 trials: int = 1,
                 analyze_coverage: bool = True,
                 store_results: bool = True)
```

## Core Classes

### OSSFuzzSDK

The main SDK facade class that provides access to all functionality.

```python
class OSSFuzzSDK:
    def __init__(self,
                 project_name: str,
                 config: Optional[Union[Dict[str, Any], SDKConfig]] = None)
```

#### Parameters

- **project_name** (`str`): Name of the OSS-Fuzz project
- **config** (`Dict` or `SDKConfig`, optional): Configuration for the SDK

#### Properties

- **project_name** (`str`): Project name
- **config** (`Dict`): Configuration dictionary
- **sdk_config** (`SDKConfig`): Configuration object
- **storage** (`StorageManager`): Storage manager instance
- **result_manager** (`ResultManager`): Result manager instance
- **benchmark_manager** (`BenchmarkManager`): Benchmark manager instance
- **local_builder** (`LocalBuilder`): Local builder instance
- **local_runner** (`LocalRunner`): Local runner instance

### Result Classes

#### BuildResult

Result of a build operation.

```python
class BuildResult:
    def __init__(self, success: bool, message: str = '',
                 build_id: Optional[str] = None, artifacts: Optional[Dict] = None)
```

**Properties:**

- `success` (`bool`): Whether the build succeeded
- `message` (`str`): Build result message
- `build_id` (`str`): Unique build identifier
- `artifacts` (`Dict`): Build artifacts and metadata
- `timestamp` (`datetime`): Build completion timestamp

#### RunResult

Result of a run operation.

```python
class RunResult:
    def __init__(self, success: bool, message: str = '',
                 run_id: Optional[str] = None, crashes: bool = False,
                 coverage_data: Optional[Dict] = None)
```

**Properties:**

- `success` (`bool`): Whether the run succeeded
- `message` (`str`): Run result message
- `run_id` (`str`): Unique run identifier
- `crashes` (`bool`): Whether crashes were detected
- `coverage_data` (`Dict`): Coverage information
- `timestamp` (`datetime`): Run completion timestamp

#### PipelineResult

Result of a full pipeline operation.

```python
class PipelineResult:
    def __init__(self, success: bool, message: str = '',
                 pipeline_id: Optional[str] = None,
                 build_results: Optional[List[BuildResult]] = None,
                 run_results: Optional[List[RunResult]] = None)
```

**Properties:**

- `success` (`bool`): Whether the pipeline succeeded
- `message` (`str`): Pipeline result message
- `pipeline_id` (`str`): Unique pipeline identifier
- `build_results` (`List[BuildResult]`): List of build results
- `run_results` (`List[RunResult]`): List of run results
- `timestamp` (`datetime`): Pipeline completion timestamp

## Build Operations

### build_fuzz_target()

Build a single fuzz target.

```python
def build_fuzz_target(self, target_spec: Union[FuzzTarget, Dict[str, Any]],
                     options: Optional[BuildOptions] = None) -> BuildResult
```

#### Parameters

- **target_spec** (`FuzzTarget` or `Dict`): Fuzz target specification
- **options** (`BuildOptions`, optional): Build configuration options

#### Returns

- **`BuildResult`**: Result of the build operation

#### Example

```python
# Using dictionary specification
target_spec = {
    'name': 'my_target',
    'source_code': '// Fuzz target source code',
    'build_script': '// Build script',
    'project_name': 'my_project',
    'language': 'c++'
}

options = BuildOptions(sanitizer='memory', timeout_seconds=1800)
result = sdk.build_fuzz_target(target_spec, options)

if result.success:
    print(f"Build successful: {result.build_id}")
    print(f"Artifacts: {result.artifacts}")
else:
    print(f"Build failed: {result.message}")
```

### build_benchmark()

Build a specific benchmark by ID.

```python
def build_benchmark(self, benchmark_id: str,
                   options: Optional[BuildOptions] = None) -> BuildResult
```

#### Parameters

- **benchmark_id** (`str`): Benchmark identifier
- **options** (`BuildOptions`, optional): Build configuration options

#### Returns

- **`BuildResult`**: Result of the build operation

#### Example

```python
result = sdk.build_benchmark('benchmark_123')
print(f"Build success: {result.success}")
```

### get_build_status()

Check the status of a build operation.

```python
def get_build_status(self, build_id: str) -> Dict[str, Any]
```

#### Parameters

- **build_id** (`str`): Build identifier

#### Returns

- **`Dict[str, Any]`**: Build status information

#### Example

```python
status = sdk.get_build_status('build_123')
print(f"Status: {status['status']}")
print(f"Message: {status['message']}")
```

### get_build_artifacts()

Retrieve build artifacts and metadata.

```python
def get_build_artifacts(self, build_id: str) -> Dict[str, Any]
```

#### Parameters

- **build_id** (`str`): Build identifier

#### Returns

- **`Dict[str, Any]`**: Build artifacts and metadata

### list_recent_builds()

List recent builds with optional filtering.

```python
def list_recent_builds(self, limit: int = 10,
                      filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]
```

#### Parameters

- **limit** (`int`): Maximum number of builds to return
- **filters** (`Dict`, optional): Filters to apply

#### Returns

- **`List[Dict[str, Any]]`**: List of build information

#### Example

```python
# Get recent successful builds
filters = {'status': 'success'}
builds = sdk.list_recent_builds(limit=5, filters=filters)
for build in builds:
    print(f"Build {build['build_id']}: {build['status']}")
```

## Execution Operations

### run_fuzz_target()

Run a single fuzz target.

```python
def run_fuzz_target(self, target_spec: Union[FuzzTarget, Dict[str, Any]],
                   build_metadata: Dict[str, Any],
                   options: Optional[RunOptions] = None) -> RunResult
```

#### Parameters

- **target_spec** (`FuzzTarget` or `Dict`): Fuzz target specification
- **build_metadata** (`Dict`): Build metadata from previous build
- **options** (`RunOptions`, optional): Run configuration options

#### Returns

- **`RunResult`**: Result of the run operation

#### Example

```python
target_spec = {
    'name': 'my_target',
    'source_code': '// Fuzz target source',
    'project_name': 'my_project',
    'language': 'c++'
}

build_metadata = {'artifacts': {'binary': '/path/to/binary'}}
options = RunOptions(duration_seconds=1800, extract_coverage=True)

result = sdk.run_fuzz_target(target_spec, build_metadata, options)
print(f"Run success: {result.success}")
print(f"Crashes detected: {result.crashes}")
print(f"Coverage: {result.coverage_data}")
```

### run_benchmark()

Run a specific benchmark (build + run).

```python
def run_benchmark(self, benchmark_id: str,
                 options: Optional[RunOptions] = None) -> RunResult
```

#### Parameters

- **benchmark_id** (`str`): Benchmark identifier
- **options** (`RunOptions`, optional): Run configuration options

#### Returns

- **`RunResult`**: Result of the run operation

#### Example

```python
options = RunOptions(duration_seconds=3600, detect_leaks=True)
result = sdk.run_benchmark('benchmark_123', options)

if result.success:
    print(f"Run completed: {result.run_id}")
    if result.crashes:
        print("Crashes detected!")
    print(f"Coverage: {result.coverage_data.get('cov_pcs', 0)} PCs")
```

### get_run_status()

Check the status of a run operation.

```python
def get_run_status(self, run_id: str) -> Dict[str, Any]
```

#### Parameters

- **run_id** (`str`): Run identifier

#### Returns

- **`Dict[str, Any]`**: Run status information

### get_run_results()

Retrieve run results and artifacts.

```python
def get_run_results(self, run_id: str) -> Dict[str, Any]
```

#### Parameters

- **run_id** (`str`): Run identifier

#### Returns

- **`Dict[str, Any]`**: Run results and artifacts

### list_recent_runs()

List recent runs with optional filtering.

```python
def list_recent_runs(self, limit: int = 10,
                    filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]
```

#### Parameters

- **limit** (`int`): Maximum number of runs to return
- **filters** (`Dict`, optional): Filters to apply

#### Returns

- **`List[Dict[str, Any]]`**: List of run information

## Workflow Orchestration

### run_full_pipeline()

Execute a complete build → run → analyze pipeline.

```python
def run_full_pipeline(self, benchmark_id: str,
                     options: Optional[PipelineOptions] = None) -> PipelineResult
```

#### Parameters

- **benchmark_id** (`str`): Benchmark identifier
- **options** (`PipelineOptions`, optional): Pipeline configuration

#### Returns

- **`PipelineResult`**: Result of the complete pipeline

#### Example

```python
# Configure pipeline options
build_opts = BuildOptions(sanitizer='address')
run_opts = RunOptions(duration_seconds=1800, extract_coverage=True)
pipeline_opts = PipelineOptions(
    build_options=build_opts,
    run_options=run_opts,
    trials=3,
    analyze_coverage=True,
    store_results=True
)

# Run pipeline
result = sdk.run_full_pipeline('benchmark_123', pipeline_opts)

print(f"Pipeline success: {result.success}")
print(f"Total trials: {len(result.build_results)}")

# Analyze results
successful_builds = sum(1 for r in result.build_results if r.success)
successful_runs = sum(1 for r in result.run_results if r.success)

print(f"Successful builds: {successful_builds}/{len(result.build_results)}")
print(f"Successful runs: {successful_runs}/{len(result.run_results)}")

# Check for crashes
crashes_detected = any(r.crashes for r in result.run_results if r.success)
print(f"Crashes detected: {crashes_detected}")
```

## Result Management

### get_benchmark_result()

Get result for a specific benchmark.

```python
def get_benchmark_result(self, benchmark_id: str, trial: Optional[int] = None) -> Optional[Any]
```

#### Parameters

- **benchmark_id** (`str`): Benchmark identifier
- **trial** (`int`, optional): Specific trial number (gets latest if not specified)

#### Returns

- **`Result`** or **`None`**: Result object or None if not found

#### Example

```python
# Get latest result
result = sdk.get_benchmark_result('benchmark_123')
if result:
    print(f"Build successful: {result.is_build_successful()}")
    print(f"Run successful: {result.is_run_successful()}")

# Get specific trial result
trial_result = sdk.get_benchmark_result('benchmark_123', trial=2)
if trial_result:
    print(f"Trial 2 result: {trial_result.trial}")
```

### get_benchmark_metrics()

Get comprehensive metrics for a benchmark.

```python
def get_benchmark_metrics(self, benchmark_id: str) -> Dict[str, Any]
```

#### Parameters

- **benchmark_id** (`str`): Benchmark identifier

#### Returns

- **`Dict[str, Any]`**: Dictionary containing comprehensive metrics

#### Example

```python
metrics = sdk.get_benchmark_metrics('benchmark_123')

print(f"Compiles: {metrics.get('compiles', False)}")
print(f"Crashes: {metrics.get('crashes', False)}")
print(f"Coverage: {metrics.get('coverage', 0.0)}%")
print(f"Line coverage diff: {metrics.get('line_coverage_diff', 0.0)}%")
print(f"Build success rate: {metrics.get('build_success_rate', 0.0)}")
print(f"Total trials: {metrics.get('trial', 0)}")
```

### get_system_metrics()

Get system-wide aggregated metrics.

```python
def get_system_metrics(self) -> Dict[str, Any]
```

#### Returns

- **`Dict[str, Any]`**: Dictionary containing system-wide metrics

#### Example

```python
metrics = sdk.get_system_metrics()

print(f"Total benchmarks: {metrics.get('total_benchmarks', 0)}")
print(f"Total builds: {metrics.get('total_builds', 0)}")
print(f"Build success rate: {metrics.get('build_success_rate', 0.0)}")
print(f"Average coverage: {metrics.get('average_coverage', 0.0)}%")
print(f"Total crashes: {metrics.get('total_crashes', 0)}")
```

### get_coverage_trend()

Get coverage trend for a benchmark.

```python
def get_coverage_trend(self, benchmark_id: str, days: int = 30) -> Union[Any, List[Dict[str, Any]]]
```

#### Parameters

- **benchmark_id** (`str`): Benchmark identifier
- **days** (`int`): Number of days to analyze

#### Returns

- **`DataFrame`** or **`List[Dict]`**: Coverage trend data (DataFrame if pandas available)

#### Example

```python
trend = sdk.get_coverage_trend('benchmark_123', days=14)

if isinstance(trend, list):
    print(f"Coverage data points: {len(trend)}")
    for point in trend[-5:]:  # Last 5 data points
        print(f"Date: {point.get('date')}, Coverage: {point.get('coverage', 0)}%")
```

### get_build_success_rate()

Get build success rate for a benchmark.

```python
def get_build_success_rate(self, benchmark_id: str, days: int = 30) -> float
```

#### Parameters

- **benchmark_id** (`str`): Benchmark identifier
- **days** (`int`): Number of days to analyze

#### Returns

- **`float`**: Build success rate (0.0 to 1.0)

#### Example

```python
success_rate = sdk.get_build_success_rate('benchmark_123', days=7)
print(f"7-day build success rate: {success_rate:.2%}")

monthly_rate = sdk.get_build_success_rate('benchmark_123', days=30)
print(f"30-day build success rate: {monthly_rate:.2%}")
```

### get_crash_summary()

Get crash summary for a benchmark.

```python
def get_crash_summary(self, benchmark_id: str, days: int = 30) -> Dict[str, Any]
```

#### Parameters

- **benchmark_id** (`str`): Benchmark identifier
- **days** (`int`): Number of days to analyze

#### Returns

- **`Dict[str, Any]`**: Dictionary containing crash statistics

#### Example

```python
crash_summary = sdk.get_crash_summary('benchmark_123', days=7)

print(f"Total crashes: {crash_summary.get('total_crashes', 0)}")
print(f"Unique crashes: {crash_summary.get('unique_crashes', 0)}")
print(f"Crash rate: {crash_summary.get('crash_rate', 0.0):.2%}")
print(f"Most recent crash: {crash_summary.get('latest_crash_date', 'None')}")
```

## Benchmark Management

### create_benchmark()

Create a new benchmark.

```python
def create_benchmark(self, benchmark_spec: Dict[str, Any]) -> bool
```

#### Parameters

- **benchmark_spec** (`Dict`): Benchmark specification dictionary

#### Returns

- **`bool`**: True if successful, False otherwise

#### Example

```python
benchmark_spec = {
    'id': 'new_benchmark_123',
    'project': 'my_project',
    'language': 'c++',
    'function_name': 'test_function',
    'function_signature': 'int test_function(const uint8_t* data, size_t size)',
    'return_type': 'int',
    'target_path': '/path/to/target.h',
    'description': 'Test benchmark for fuzzing'
}

success = sdk.create_benchmark(benchmark_spec)
if success:
    print("Benchmark created successfully")
else:
    print("Failed to create benchmark")
```

### update_benchmark()

Update an existing benchmark.

```python
def update_benchmark(self, benchmark_id: str, updates: Dict[str, Any]) -> bool
```

#### Parameters

- **benchmark_id** (`str`): Benchmark identifier
- **updates** (`Dict`): Dictionary of updates to apply

#### Returns

- **`bool`**: True if successful, False otherwise

#### Example

```python
updates = {
    'description': 'Updated benchmark description',
    'function_signature': 'int updated_function(const char* input)',
    'tags': ['security', 'performance']
}

success = sdk.update_benchmark('benchmark_123', updates)
if success:
    print("Benchmark updated successfully")
```

### delete_benchmark()

Delete a benchmark.

```python
def delete_benchmark(self, benchmark_id: str) -> bool
```

#### Parameters

- **benchmark_id** (`str`): Benchmark identifier

#### Returns

- **`bool`**: True if successful, False otherwise

### list_benchmarks()

List available benchmarks with filtering.

```python
def list_benchmarks(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]
```

#### Parameters

- **filters** (`Dict`, optional): Filters to apply

#### Returns

- **`List[Dict[str, Any]]`**: List of benchmark information

#### Example

```python
# List all benchmarks
all_benchmarks = sdk.list_benchmarks()
print(f"Total benchmarks: {len(all_benchmarks)}")

# Filter by language
cpp_benchmarks = sdk.list_benchmarks(filters={'language': 'c++'})
print(f"C++ benchmarks: {len(cpp_benchmarks)}")

# Filter by project
project_benchmarks = sdk.list_benchmarks(filters={'project': 'my_project'})
for benchmark in project_benchmarks:
    print(f"Benchmark: {benchmark['id']} - {benchmark['function_name']}")
```

### search_benchmarks()

Search benchmarks by query.

```python
def search_benchmarks(self, query: str, limit: int = 10) -> List[Dict[str, Any]]
```

#### Parameters

- **query** (`str`): Search query string
- **limit** (`int`): Maximum number of results

#### Returns

- **`List[Dict[str, Any]]`**: List of matching benchmark information

#### Example

```python
# Search for benchmarks containing "crypto"
results = sdk.search_benchmarks('crypto', limit=5)
for result in results:
    print(f"Found: {result['id']} - {result['description']}")
```

## Export & Analysis

### export_results()

Export results for multiple benchmarks.

```python
def export_results(self, benchmark_ids: List[str],
                  format: str = 'json',
                  output_path: Optional[str] = None) -> str
```

#### Parameters

- **benchmark_ids** (`List[str]`): List of benchmark identifiers
- **format** (`str`): Export format ('json', 'csv', 'xlsx')
- **output_path** (`str`, optional): Optional output file path

#### Returns

- **`str`**: Path to exported file

#### Example

```python
# Export multiple benchmarks to JSON
benchmark_ids = ['bench_1', 'bench_2', 'bench_3']
output_path = sdk.export_results(benchmark_ids, format='json')
print(f"Results exported to: {output_path}")

# Export to custom path with CSV format
custom_path = '/path/to/my_export.csv'
csv_path = sdk.export_results(
    benchmark_ids,
    format='csv',
    output_path=custom_path
)
print(f"CSV export saved to: {csv_path}")

# Export to Excel format
xlsx_path = sdk.export_results(benchmark_ids, format='xlsx')
print(f"Excel export saved to: {xlsx_path}")
```

### generate_comparison_report()

Generate a comparison report for multiple benchmarks.

```python
def generate_comparison_report(self, benchmark_ids: List[str],
                             days: int = 30) -> Dict[str, Any]
```

#### Parameters

- **benchmark_ids** (`List[str]`): List of benchmark identifiers to compare
- **days** (`int`): Number of days to analyze

#### Returns

- **`Dict[str, Any]`**: Dictionary containing comparison report

#### Example

```python
benchmark_ids = ['bench_1', 'bench_2', 'bench_3']
report = sdk.generate_comparison_report(benchmark_ids, days=14)

print(f"Comparison report generated at: {report['comparison_timestamp']}")
print(f"Analyzed {report['benchmark_count']} benchmarks over {report['analysis_period_days']} days")

# Analyze each benchmark
for benchmark_id, data in report['benchmarks'].items():
    if 'error' in data:
        print(f"{benchmark_id}: Error - {data['error']}")
        continue

    metrics = data['metrics']
    build_rate = data['build_success_rate']
    crash_summary = data['crash_summary']

    print(f"\n{benchmark_id}:")
    print(f"  Build success rate: {build_rate:.2%}")
    print(f"  Coverage: {metrics.get('coverage', 0)}%")
    print(f"  Total crashes: {crash_summary.get('total_crashes', 0)}")
```

## Historical Data Analysis

### generate_project_report()

Generate a comprehensive project report.

```python
def generate_project_report(self, days: int = 30,
                          include_details: bool = True) -> Dict[str, Any]
```

#### Parameters

- **days** (`int`): Number of days to analyze
- **include_details** (`bool`): Whether to include detailed information

#### Returns

- **`Dict[str, Any]`**: Comprehensive project report

#### Example

```python
# Generate monthly report
report = sdk.generate_project_report(days=30, include_details=True)

print(f"Project: {report['project_name']}")
print(f"Report period: {report['start_date']} to {report['end_date']}")

# Build summary
build_summary = report.get('build_summary', {})
print(f"\nBuild Summary:")
print(f"  Total builds: {build_summary.get('total_builds', 0)}")
print(f"  Success rate: {build_summary.get('success_rate', 0):.2%}")

# Coverage summary
coverage_summary = report.get('coverage_summary', {})
print(f"\nCoverage Summary:")
print(f"  Average coverage: {coverage_summary.get('average_coverage', 0):.1f}%")
print(f"  Coverage trend: {coverage_summary.get('trend', 'unknown')}")

# Crash summary
crash_summary = report.get('crash_summary', {})
print(f"\nCrash Summary:")
print(f"  Total crashes: {crash_summary.get('total_crashes', 0)}")
print(f"  Unique crashes: {crash_summary.get('unique_crashes', 0)}")
```

### analyze_fuzzing_efficiency()

Analyze fuzzing efficiency over a time period.

```python
def analyze_fuzzing_efficiency(self, days: int = 30) -> Dict[str, Any]
```

#### Parameters

- **days** (`int`): Number of days to analyze

#### Returns

- **`Dict[str, Any]`**: Fuzzing efficiency analysis

#### Example

```python
efficiency = sdk.analyze_fuzzing_efficiency(days=14)

print(f"Project: {efficiency['project_name']}")
print(f"Analysis period: {efficiency['period_days']} days")

# Overall efficiency
overall = efficiency['overall_efficiency']
print(f"\nOverall Efficiency: {overall['overall_efficiency']:.1f}% ({overall['level']})")

# Category scores
scores = overall['category_scores']
print(f"Build efficiency: {scores['build']:.1f}%")
print(f"Coverage efficiency: {scores['coverage']:.1f}%")
print(f"Crash discovery: {scores['crash']:.1f}%")
print(f"Corpus growth: {scores['corpus']:.1f}%")

# Detailed analysis
build_eff = efficiency['build_efficiency']
print(f"\nBuild Efficiency:")
print(f"  Builds per day: {build_eff['builds_per_day']:.1f}")
print(f"  Success rate: {build_eff['success_rate']:.2%}")

coverage_eff = efficiency['coverage_efficiency']
print(f"\nCoverage Efficiency:")
print(f"  Coverage velocity: {coverage_eff['coverage_velocity']:.2f}%/day")
print(f"  Current coverage: {coverage_eff['current_coverage']:.1f}%")
```

### get_project_summary()

Get a quick project summary.

```python
def get_project_summary(self) -> Dict[str, Any]
```

#### Returns

- **`Dict[str, Any]`**: Project summary information

#### Example

```python
summary = sdk.get_project_summary()

print(f"Project: {summary['project_name']}")
print(f"Last updated: {summary['last_updated']}")
print(f"Total benchmarks: {summary.get('total_benchmarks', 0)}")
print(f"Latest coverage: {summary.get('latest_coverage', 'N/A')}")
print(f"Recent crashes: {summary.get('recent_crashes', 0)}")
print(f"Last successful build: {summary.get('last_successful_build', 'None')}")
```

## Error Handling

The OSS-Fuzz SDK provides comprehensive error handling with graceful degradation when components are not available.

### Exception Types

- **`OSSFuzzSDKError`**: General SDK errors
- **`OSSFuzzSDKConfigError`**: Configuration-related errors
- **`BuilderError`**: Build operation errors
- **`FuzzRunnerError`**: Execution operation errors
- **`BenchmarkError`**: Benchmark management errors

### Error Handling Patterns

#### Graceful Degradation

```python
# SDK handles missing components gracefully
sdk = OSSFuzzSDK('my_project')

# Methods return appropriate defaults when components unavailable
metrics = sdk.get_benchmark_metrics('benchmark_id')  # Returns empty dict
result = sdk.get_benchmark_result('benchmark_id')    # Returns None
builds = sdk.list_recent_builds()                    # Returns empty list
```

#### Exception Handling

```python
from ossfuzz_py.errors import OSSFuzzSDKError, BuilderError

try:
    # Operations that might fail
    result = sdk.run_full_pipeline('benchmark_id')

    if not result.success:
        print(f"Pipeline failed: {result.message}")

except OSSFuzzSDKError as e:
    print(f"SDK error: {e}")
except BuilderError as e:
    print(f"Build error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

#### Component Availability Checking

```python
# Check component availability before use
if sdk.result_manager:
    metrics = sdk.get_benchmark_metrics('benchmark_id')
else:
    print("ResultManager not available")

if sdk.local_builder:
    result = sdk.build_benchmark('benchmark_id')
else:
    print("Builder not available")
```

## Examples

### Complete Workflow Example

```python
from ossfuzz_py.core.ossfuzz_sdk import (
    OSSFuzzSDK, SDKConfig, PipelineOptions, BuildOptions, RunOptions
)

# Initialize SDK with custom configuration
config = SDKConfig(
    storage_backend='local',
    storage_path='/tmp/ossfuzz_data',
    log_level='INFO',
    enable_caching=True
)

sdk = OSSFuzzSDK('libpng', config)

# Configure pipeline for comprehensive testing
build_opts = BuildOptions(
    sanitizer='address',
    architecture='x86_64',
    timeout_seconds=1800
)

run_opts = RunOptions(
    duration_seconds=3600,
    detect_leaks=True,
    extract_coverage=True,
    max_memory_mb=2048
)

pipeline_opts = PipelineOptions(
    build_options=build_opts,
    run_options=run_opts,
    trials=5,
    analyze_coverage=True,
    store_results=True
)

# Run comprehensive analysis
benchmark_ids = ['png_decode_1', 'png_decode_2', 'png_encode_1']

for benchmark_id in benchmark_ids:
    print(f"\n=== Processing {benchmark_id} ===")

    # Run full pipeline
    pipeline_result = sdk.run_full_pipeline(benchmark_id, pipeline_opts)

    if pipeline_result.success:
        print(f"✅ Pipeline completed successfully")

        # Analyze results
        successful_builds = sum(1 for r in pipeline_result.build_results if r.success)
        successful_runs = sum(1 for r in pipeline_result.run_results if r.success)
        crashes_found = any(r.crashes for r in pipeline_result.run_results if r.success)

        print(f"   Builds: {successful_builds}/{len(pipeline_result.build_results)}")
        print(f"   Runs: {successful_runs}/{len(pipeline_result.run_results)}")
        print(f"   Crashes found: {crashes_found}")

        # Get detailed metrics
        metrics = sdk.get_benchmark_metrics(benchmark_id)
        print(f"   Coverage: {metrics.get('coverage', 0):.1f}%")
        print(f"   Build success rate: {metrics.get('build_success_rate', 0):.2%}")

    else:
        print(f"❌ Pipeline failed: {pipeline_result.message}")

# Generate comprehensive reports
print("\n=== Generating Reports ===")

# Export results
export_path = sdk.export_results(benchmark_ids, format='json')
print(f"Results exported to: {export_path}")

# Generate comparison report
comparison = sdk.generate_comparison_report(benchmark_ids, days=30)
print(f"Comparison report generated for {comparison['benchmark_count']} benchmarks")

# Generate project report
project_report = sdk.generate_project_report(days=30, include_details=True)
print(f"Project report generated for {project_report['project_name']}")

# Analyze efficiency
efficiency = sdk.analyze_fuzzing_efficiency(days=30)
overall_score = efficiency['overall_efficiency']['overall_efficiency']
print(f"Overall fuzzing efficiency: {overall_score:.1f}%")
```

### Batch Processing Example

```python
# Process multiple projects
projects = ['libpng', 'libjpeg', 'zlib']

for project in projects:
    print(f"\n=== Processing Project: {project} ===")

    # Initialize SDK for each project
    sdk = OSSFuzzSDK(project)

    # Get project summary
    summary = sdk.get_project_summary()
    print(f"Total benchmarks: {summary.get('total_benchmarks', 0)}")

    # List all benchmarks
    benchmarks = sdk.list_benchmarks()

    # Run quick analysis on each benchmark
    for benchmark in benchmarks[:3]:  # Limit to first 3
        benchmark_id = benchmark['id']

        # Get metrics
        metrics = sdk.get_benchmark_metrics(benchmark_id)
        build_rate = sdk.get_build_success_rate(benchmark_id, days=7)

        print(f"  {benchmark_id}:")
        print(f"    Build success rate: {build_rate:.2%}")
        print(f"    Coverage: {metrics.get('coverage', 0):.1f}%")

        # Check for recent crashes
        crash_summary = sdk.get_crash_summary(benchmark_id, days=7)
        if crash_summary.get('total_crashes', 0) > 0:
            print(f"    ⚠️  {crash_summary['total_crashes']} crashes in last 7 days")
```

## Best Practices

### Configuration Management

1. **Use Environment Variables**: Set up environment variables for consistent configuration across environments.

```bash
export OSSFUZZ_HISTORY_STORAGE_BACKEND=gcs
export GCS_BUCKET_NAME=my-ossfuzz-bucket
export WORK_DIR=/tmp/ossfuzz_work
```

2. **Create Reusable Configurations**: Define standard configurations for different use cases.

```python
# Development configuration
dev_config = SDKConfig(
    storage_backend='local',
    storage_path='/tmp/ossfuzz_dev',
    log_level='DEBUG',
    enable_caching=False
)

# Production configuration
prod_config = SDKConfig(
    storage_backend='gcs',
    gcs_bucket_name='prod-ossfuzz-bucket',
    log_level='INFO',
    enable_caching=True,
    timeout_seconds=7200
)
```

### Performance Optimization

1. **Use Appropriate Trial Counts**: Balance thoroughness with execution time.

```python
# Quick testing
quick_opts = PipelineOptions(trials=1)

# Thorough testing
thorough_opts = PipelineOptions(trials=5)

# Comprehensive testing
comprehensive_opts = PipelineOptions(trials=10)
```

2. **Enable Caching**: Use caching for repeated operations.

```python
config = SDKConfig(enable_caching=True)
```

3. **Batch Operations**: Process multiple benchmarks efficiently.

```python
# Batch export
all_benchmark_ids = [b['id'] for b in sdk.list_benchmarks()]
sdk.export_results(all_benchmark_ids, format='json')

# Batch comparison
sdk.generate_comparison_report(all_benchmark_ids, days=30)
```

### Error Handling Best Practices

1. **Check Component Availability**: Always check if required components are available.

```python
if not sdk.result_manager:
    print("Warning: ResultManager not available, some features disabled")

if not sdk.local_builder:
    print("Warning: Builder not available, build operations disabled")
```

2. **Handle Partial Failures**: Design workflows to handle partial failures gracefully.

```python
pipeline_result = sdk.run_full_pipeline(benchmark_id, options)

if not pipeline_result.success:
    # Check individual components
    if pipeline_result.build_results:
        build_success = any(r.success for r in pipeline_result.build_results)
        if build_success:
            print("At least one build succeeded, investigating run failures...")
```

3. **Use Timeouts**: Set appropriate timeouts for long-running operations.

```python
build_opts = BuildOptions(timeout_seconds=1800)  # 30 minutes
run_opts = RunOptions(duration_seconds=3600)     # 1 hour
```

### Monitoring and Logging

1. **Configure Appropriate Log Levels**: Use different log levels for different environments.

```python
# Development
dev_config = SDKConfig(log_level='DEBUG')

# Production
prod_config = SDKConfig(log_level='INFO')
```

2. **Monitor Key Metrics**: Regularly check important metrics.

```python
# Daily monitoring
def daily_health_check(sdk):
    summary = sdk.get_project_summary()
    system_metrics = sdk.get_system_metrics()

    print(f"Build success rate: {system_metrics.get('build_success_rate', 0):.2%}")
    print(f"Total crashes: {system_metrics.get('total_crashes', 0)}")
    print(f"Average coverage: {system_metrics.get('average_coverage', 0):.1f}%")

    return system_metrics
```

3. **Set Up Alerts**: Monitor for concerning trends.

```python
def check_alerts(sdk, benchmark_id):
    build_rate = sdk.get_build_success_rate(benchmark_id, days=7)
    crash_summary = sdk.get_crash_summary(benchmark_id, days=1)

    if build_rate < 0.8:  # Less than 80% success rate
        print(f"⚠️  Alert: Low build success rate for {benchmark_id}: {build_rate:.2%}")

    if crash_summary.get('total_crashes', 0) > 10:  # More than 10 crashes per day
        print(f"🚨 Alert: High crash rate for {benchmark_id}: {crash_summary['total_crashes']} crashes")
```

### Data Management

1. **Regular Exports**: Regularly export data for backup and analysis.

```python
# Weekly export
import datetime

def weekly_export(sdk):
    timestamp = datetime.datetime.now().strftime("%Y%m%d")
    all_benchmarks = [b['id'] for b in sdk.list_benchmarks()]

    export_path = sdk.export_results(
        all_benchmarks,
        format='json',
        output_path=f'weekly_export_{timestamp}.json'
    )

    return export_path
```

2. **Clean Up Old Data**: Implement data retention policies.

```python
# This would be implemented based on your storage backend
def cleanup_old_data(sdk, days_to_keep=90):
    # Implementation depends on storage backend
    pass
```

---

For more information and updates, please refer to the [OSS-Fuzz SDK GitHub repository](https://github.com/google/oss-fuzz-gen).
