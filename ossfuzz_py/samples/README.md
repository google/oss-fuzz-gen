# OSS-Fuzz SDK Samples

This directory contains practical examples demonstrating how to use the OSS-Fuzz SDK for various fuzzing workflows and use cases.

## Sample Structure

```
samples/
├── README.md                          # This file
├── basic/                             # Basic usage examples
│   ├── 01_quick_start.py             # Getting started with the SDK
│   ├── 02_configuration.py           # Configuration management
│   └── 03_simple_benchmark.py        # Running a single benchmark
├── intermediate/                      # Intermediate examples
│   ├── 01_build_operations.py        # Build operations and management
│   ├── 02_execution_workflows.py     # Execution and run management
│   ├── 03_result_analysis.py         # Result analysis and metrics
│   └── 04_pipeline_automation.py     # Automated pipeline workflows
├── advanced/                          # Advanced use cases
│   ├── 01_batch_processing.py        # Batch processing multiple projects
│   ├── 02_custom_workflows.py        # Custom workflow orchestration
│   ├── 03_monitoring_alerts.py       # Monitoring and alerting systems
│   └── 04_data_export_analysis.py    # Data export and analysis
├── production/                        # Production deployment examples
│   ├── 01_enterprise_config.py       # Enterprise configuration setup
│   ├── 02_ci_cd_integration.py       # CI/CD pipeline integration
│   ├── 03_monitoring_dashboard.py    # Monitoring dashboard setup
│   └── 04_automated_reporting.py     # Automated reporting system
├── utilities/                         # Utility scripts and helpers
│   ├── config_generator.py           # Configuration file generator
│   ├── health_checker.py             # System health checker
│   ├── data_migrator.py              # Data migration utilities
│   └── benchmark_validator.py        # Benchmark validation tools
└── data/                             # Sample data and configurations
    ├── sample_benchmarks.json        # Sample benchmark definitions
    ├── sample_configs/               # Sample configuration files
    └── test_data/                    # Test data for examples
```

## Getting Started

### Prerequisites

1. **Set up environment variables:**
   ```bash
   export OSSFUZZ_HISTORY_STORAGE_BACKEND=local
   export OSSFUZZ_HISTORY_STORAGE_PATH=/tmp/ossfuzz_data
   export WORK_DIR=/tmp/ossfuzz_work
   ```

2. **Run your first example:**
   ```bash
   cd samples/basic
   python 01_quick_start.py
   ```

## Sample Categories

### Basic Examples (`basic/`)

Perfect for users new to the OSS-Fuzz SDK. These examples cover:

- **Quick Start**: Initialize the SDK and run your first benchmark
- **Configuration**: Set up SDK configuration for different environments
- **Simple Benchmark**: Run a single benchmark with basic options

**Start here if you're new to the SDK!**

### Intermediate Examples (`intermediate/`)

For users familiar with basic concepts who want to explore more features:

- **Build Operations**: Manage build processes and artifacts
- **Execution Workflows**: Control fuzzing execution and monitoring
- **Result Analysis**: Analyze results and extract meaningful metrics
- **Pipeline Automation**: Automate complete build → run → analyze workflows

### Advanced Examples (`advanced/`)

For experienced users implementing complex workflows:

- **Batch Processing**: Process multiple projects and benchmarks efficiently
- **Custom Workflows**: Create custom orchestration and automation
- **Monitoring & Alerts**: Set up monitoring systems and alerting
- **Data Export & Analysis**: Advanced data analysis and reporting

### Production Examples (`production/`)

Enterprise-ready examples for production deployment:

- **Enterprise Configuration**: Production-grade configuration management
- **CI/CD Integration**: Integrate with continuous integration systems
- **Monitoring Dashboard**: Set up comprehensive monitoring
- **Automated Reporting**: Create automated reporting systems

### Utilities (`utilities/`)

Helper scripts and tools to support your fuzzing workflows:

- **Configuration Generator**: Generate configuration files
- **Health Checker**: Monitor system health and component status
- **Data Migrator**: Migrate data between storage backends
- **Benchmark Validator**: Validate benchmark definitions

## Use Case Guide

### I want to...

#### **Get started quickly**
→ Start with `basic/01_quick_start.py`

#### **Set up configuration for my environment**
→ Check `basic/02_configuration.py` and `production/01_enterprise_config.py`

#### **Run a single benchmark**
→ Use `basic/03_simple_benchmark.py`

#### **Automate my fuzzing pipeline**
→ Look at `intermediate/04_pipeline_automation.py`

#### **Process multiple projects**
→ Try `advanced/01_batch_processing.py`

#### **Set up monitoring and alerts**
→ Explore `advanced/03_monitoring_alerts.py`

#### **Integrate with CI/CD**
→ Check `production/02_ci_cd_integration.py`

#### **Export and analyze data**
→ Use `advanced/04_data_export_analysis.py`

#### **Deploy in production**
→ Review all examples in `production/`

## Running the Examples

### Basic Usage

```bash
# Navigate to the samples directory
cd samples

# Run a basic example
python basic/01_quick_start.py

# Run with custom configuration
python basic/02_configuration.py --config-file data/sample_configs/dev.json

# Run an intermediate example
python intermediate/01_build_operations.py --project libpng
```

### Advanced Usage

```bash
# Batch processing example
python advanced/01_batch_processing.py --projects libpng,libjpeg,zlib

# Custom workflow with monitoring
python advanced/02_custom_workflows.py --enable-monitoring

# Production deployment example
python production/01_enterprise_config.py --environment production
```

## Customization

### Modifying Examples

All examples are designed to be easily customizable:

1. **Configuration**: Modify the configuration sections at the top of each file
2. **Parameters**: Adjust parameters like project names, timeouts, and options
3. **Workflows**: Customize the workflow steps to match your requirements
4. **Output**: Modify output formats and destinations

### Creating Your Own Examples

Use the existing examples as templates:

1. Copy a similar example as a starting point
2. Modify the configuration and parameters
3. Customize the workflow logic
4. Add your specific requirements
5. Test thoroughly before production use

## Sample Data

The `data/` directory contains:

- **Sample benchmark definitions** for testing
- **Configuration templates** for different environments
- **Test data** for running examples without real projects

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure the SDK is installed and in your Python path
2. **Configuration Errors**: Check environment variables and configuration files
3. **Permission Errors**: Ensure proper permissions for work directories
4. **Component Unavailable**: Some examples require optional dependencies

### Getting Help

1. **Check the logs**: Most examples include detailed logging
2. **Review the API documentation**: See `docs/API_DOCUMENTATION.md`
3. **Run with debug mode**: Set `log_level='DEBUG'` in configuration
4. **Check component availability**: Use the health checker utility

## Contributing

We welcome contributions to the samples! To add a new example:

1. Choose the appropriate category directory
2. Follow the existing naming convention
3. Include comprehensive comments and documentation
4. Add error handling and logging
5. Test thoroughly with different configurations
6. Update this README with your example

## License

These samples are provided under the same license as the OSS-Fuzz SDK project.