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
# pylint: disable=invalid-name,line-too-long,redefined-outer-name
"""
OSS-Fuzz SDK Configuration Example

This example demonstrates different ways to configure the OSS-Fuzz SDK
for various environments and use cases.

What this example covers:
- Basic configuration with SDKConfig
- Environment variable configuration
- Different storage backends
- Configuration for different environments (dev, staging, prod)
- Configuration validation and troubleshooting

Prerequisites:
- OSS-Fuzz SDK installed: pip install ossfuzz-py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Add the parent directory to the path so we can import the SDK
sys.path.append(str(Path(__file__).parent.parent.parent))


def demonstrate_basic_configuration():
  """Demonstrate basic SDK configuration."""
  print("📋 Basic Configuration")
  print("-" * 30)

  try:
    from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK, SDKConfig

    # Method 1: Default configuration
    print("1. Default Configuration:")
    sdk_default = OSSFuzzSDK('my_project')
    print(
        f"   ✅ Default storage backend: {sdk_default.config.get('storage_backend', 'local')}"
    )
    print(
        f"   ✅ Default work dir: {sdk_default.config.get('work_dir', '/tmp')}")

    # Method 2: Dictionary configuration
    print("\n2. Dictionary Configuration:")
    config_dict = {
        'storage_backend': 'local',
        'storage_path': '/tmp/ossfuzz_data',
        'log_level': 'INFO',
        'enable_caching': True,
        'timeout_seconds': 3600
    }

    sdk_dict = OSSFuzzSDK('my_project', config_dict)
    print(f"   ✅ Storage backend: {sdk_dict.config['storage_backend']}")
    print(f"   ✅ Storage path: {sdk_dict.config['storage_path']}")
    print(f"   ✅ Log level: {sdk_dict.config['log_level']}")

    # Method 3: SDKConfig object
    print("\n3. SDKConfig Object:")
    sdk_config = SDKConfig(storage_backend='local',
                           storage_path='/tmp/ossfuzz_advanced',
                           log_level='DEBUG',
                           enable_caching=False,
                           timeout_seconds=7200,
                           max_retries=5)

    sdk_obj = OSSFuzzSDK('my_project', sdk_config)
    print(f"   ✅ Storage backend: {sdk_obj.sdk_config.storage_backend}")
    print(f"   ✅ Log level: {sdk_obj.sdk_config.log_level}")
    print(f"   ✅ Caching enabled: {sdk_obj.sdk_config.enable_caching}")
    print(f"   ✅ Timeout: {sdk_obj.sdk_config.timeout_seconds}s")
    print(f"   ✅ Max retries: {sdk_obj.sdk_config.max_retries}")

    return True

  except Exception as e:
    print(f"❌ Configuration demonstration failed: {e}")
    return False


def demonstrate_environment_configurations():
  """Demonstrate configurations for different environments."""
  print("\n🌍 Environment-Specific Configurations")
  print("-" * 40)

  try:
    from ossfuzz_py.core.ossfuzz_sdk import SDKConfig

    # Development configuration
    print("1. Development Environment:")
    dev_config = SDKConfig(
        storage_backend='local',
        storage_path='/tmp/ossfuzz_dev',
        log_level='DEBUG',
        enable_caching=False,  # Disable caching for development
        timeout_seconds=1800,  # Shorter timeout for dev
        max_retries=2)

    print(
        f"   ✅ Storage: {dev_config.storage_backend} at {dev_config.storage_path}"
    )
    print(f"   ✅ Logging: {dev_config.log_level} level")
    print(
        f"   ✅ Caching: {'Enabled' if dev_config.enable_caching else 'Disabled'}"
    )
    print(f"   ✅ Timeout: {dev_config.timeout_seconds}s")

    # Staging configuration
    print("\n2. Staging Environment:")
    staging_config = SDKConfig(
        storage_backend='local',  # Could be 'gcs' for cloud staging
        storage_path='/var/ossfuzz/staging',
        log_level='INFO',
        enable_caching=True,
        timeout_seconds=3600,
        max_retries=3)

    print(
        f"   ✅ Storage: {staging_config.storage_backend} at {staging_config.storage_path}"
    )
    print(f"   ✅ Logging: {staging_config.log_level} level")
    print(
        f"   ✅ Caching: {'Enabled' if staging_config.enable_caching else 'Disabled'}"
    )
    print(f"   ✅ Timeout: {staging_config.timeout_seconds}s")

    # Production configuration
    print("\n3. Production Environment:")
    prod_config = SDKConfig(
        storage_backend='gcs',  # Use cloud storage for production
        gcs_bucket_name='prod-ossfuzz-bucket',
        log_level='WARNING',  # Less verbose logging
        enable_caching=True,
        timeout_seconds=7200,  # Longer timeout for production
        max_retries=5)

    print(f"   ✅ Storage: {prod_config.storage_backend}")
    print(f"   ✅ GCS Bucket: {prod_config.gcs_bucket_name}")
    print(f"   ✅ Logging: {prod_config.log_level} level")
    print(
        f"   ✅ Caching: {'Enabled' if prod_config.enable_caching else 'Disabled'}"
    )
    print(f"   ✅ Timeout: {prod_config.timeout_seconds}s")
    print(f"   ✅ Max retries: {prod_config.max_retries}")

    return True

  except Exception as e:
    print(f"❌ Environment configuration demonstration failed: {e}")
    return False


def demonstrate_environment_variables():
  """Demonstrate configuration using environment variables."""
  print("\n🔧 Environment Variable Configuration")
  print("-" * 40)

  # Show current environment variables
  print("1. Current Environment Variables:")
  env_vars = [
      'OSSFUZZ_HISTORY_STORAGE_BACKEND', 'OSSFUZZ_HISTORY_STORAGE_PATH',
      'GCS_BUCKET_NAME', 'WORK_DIR', 'OSS_FUZZ_DIR'
  ]

  for var in env_vars:
    value = os.environ.get(var, 'Not set')
    print(f"   {var}: {value}")

  # Demonstrate setting environment variables programmatically
  print("\n2. Setting Environment Variables Programmatically:")

  # Save original values
  original_values = {}
  for var in env_vars:
    original_values[var] = os.environ.get(var)

  try:
    # Set temporary environment variables
    os.environ['OSSFUZZ_HISTORY_STORAGE_BACKEND'] = 'local'
    os.environ['OSSFUZZ_HISTORY_STORAGE_PATH'] = '/tmp/ossfuzz_env_demo'
    os.environ['WORK_DIR'] = '/tmp/ossfuzz_work_demo'

    print("   ✅ Set OSSFUZZ_HISTORY_STORAGE_BACKEND=local")
    print("   ✅ Set OSSFUZZ_HISTORY_STORAGE_PATH=/tmp/ossfuzz_env_demo")
    print("   ✅ Set WORK_DIR=/tmp/ossfuzz_work_demo")

    # Initialize SDK to see environment variable loading
    from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK

    sdk = OSSFuzzSDK('env_demo_project')
    print("\n   ✅ SDK loaded with environment configuration:")
    print(
        f"      Storage backend: {sdk.config.get('storage_backend', 'default')}"
    )
    print(f"      Storage path: {sdk.config.get('storage_path', 'default')}")
    print(f"      Work dir: {sdk.config.get('work_dir', 'default')}")

  finally:
    # Restore original environment variables
    for var, value in original_values.items():
      if value is None:
        os.environ.pop(var, None)
      else:
        os.environ[var] = value

  print("\n   ✅ Environment variables restored")


def demonstrate_configuration_validation():
  """Demonstrate configuration validation and troubleshooting."""
  print("\n🔍 Configuration Validation")
  print("-" * 30)

  try:
    from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK, SDKConfig

    # Test 1: Valid configuration
    print("1. Testing Valid Configuration:")
    valid_config = SDKConfig(storage_backend='local',
                             storage_path='/tmp/valid_test',
                             log_level='INFO')
    try:
      sdk = OSSFuzzSDK('test_project', valid_config)
      print("   ✅ Valid configuration accepted")

    except Exception as e:
      print(f"   ❌ Valid configuration rejected: {e}")

    # Test 2: Invalid project name
    print("\n2. Testing Invalid Project Name:")
    try:
      sdk = OSSFuzzSDK('', valid_config)  # Empty project name
      print("   ❌ Empty project name should have been rejected")
    except Exception as e:
      print(f"   ✅ Empty project name correctly rejected: {type(e).__name__}")

    # Test 3: Configuration conversion
    print("\n3. Testing Configuration Conversion:")
    config_dict = {
        'storage_backend': 'local',
        'log_level': 'DEBUG',
        'enable_caching': True
    }

    sdk = OSSFuzzSDK('test_project', config_dict)
    print("   ✅ Dictionary config converted successfully")
    print(f"      SDK config type: {type(sdk.sdk_config).__name__}")
    print(f"      Storage backend: {sdk.sdk_config.storage_backend}")
    print(f"      Log level: {sdk.sdk_config.log_level}")

    return True

  except Exception as e:
    print(f"❌ Configuration validation failed: {e}")
    return False


def demonstrate_configuration_best_practices():
  """Demonstrate configuration best practices."""
  print("\n💡 Configuration Best Practices")
  print("-" * 35)

  print("1. Use Environment Variables for Deployment:")
  print("   export OSSFUZZ_HISTORY_STORAGE_BACKEND=gcs")
  print("   export GCS_BUCKET_NAME=my-production-bucket")
  print("   export WORK_DIR=/var/ossfuzz/work")

  print("\n2. Create Configuration Templates:")

  # Create sample configuration files
  configs = {
      'development': {
          'storage_backend': 'local',
          'storage_path': '/tmp/ossfuzz_dev',
          'log_level': 'DEBUG',
          'enable_caching': False,
          'timeout_seconds': 1800
      },
      'production': {
          'storage_backend': 'gcs',
          'gcs_bucket_name': 'prod-ossfuzz-bucket',
          'log_level': 'INFO',
          'enable_caching': True,
          'timeout_seconds': 7200,
          'max_retries': 5
      }
  }

  # Save configuration files
  config_dir = Path(tempfile.gettempdir()) / 'ossfuzz_configs'
  config_dir.mkdir(exist_ok=True)

  for env_name, config in configs.items():
    config_file = config_dir / f'{env_name}.json'
    with open(config_file, 'w') as f:
      json.dump(config, f, indent=2)
    print(f"   ✅ Created {config_file}")

  print("\n3. Load Configuration from File:")

  # Demonstrate loading configuration from file
  dev_config_file = config_dir / 'development.json'
  if dev_config_file.exists():
    with open(dev_config_file, 'r') as f:
      config_data = json.load(f)

    from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK
    sdk = OSSFuzzSDK('file_config_project', config_data)
    print(f"   ✅ Loaded configuration from {dev_config_file}")
    print(f"      Storage backend: {sdk.config['storage_backend']}")
    print(f"      Log level: {sdk.config['log_level']}")

  print("\n4. Configuration Hierarchy (Priority Order):")
  print("   1. Explicit configuration parameters (highest priority)")
  print("   2. Configuration file parameters")
  print("   3. Environment variables")
  print("   4. Default values (lowest priority)")

  print("\n5. Security Best Practices:")
  print("   • Never hardcode sensitive information (API keys, passwords)")
  print("   • Use environment variables for sensitive configuration")
  print("   • Restrict file permissions on configuration files")
  print("   • Use different configurations for different environments")


def main():
  """Main function demonstrating configuration management."""
  print("⚙️  OSS-Fuzz SDK Configuration Example")
  print("=" * 50)

  success = True

  # Run all demonstrations
  success &= demonstrate_basic_configuration()
  success &= demonstrate_environment_configurations()

  try:
    demonstrate_environment_variables()
  except Exception as e:
    print(f"⚠️  Environment variable demo had issues: {e}")

  success &= demonstrate_configuration_validation()

  try:
    demonstrate_configuration_best_practices()
  except Exception as e:
    print(f"⚠️  Best practices demo had issues: {e}")

  # Summary
  print("\n🎉 Configuration Example Summary")
  print("=" * 35)
  print("✅ Configuration methods demonstrated:")
  print("   • Default configuration")
  print("   • Dictionary configuration")
  print("   • SDKConfig object configuration")
  print("   • Environment variable configuration")
  print("   • Configuration file loading")

  print("\n📋 Key takeaways:")
  print("   • Use SDKConfig for type safety and validation")
  print("   • Environment variables provide deployment flexibility")
  print("   • Different environments need different configurations")
  print("   • Always validate your configuration")
  print("   • Follow security best practices")

  print("\n🚀 Next steps:")
  print("   • Try basic/03_simple_benchmark.py with your configuration")
  print("   • Explore intermediate examples for advanced usage")
  print("   • Set up your production configuration")

  return success


if __name__ == '__main__':
  try:
    success = main()
    if success:
      print("\n🎯 Configuration example completed successfully!")
      sys.exit(0)
    else:
      print("\n⚠️  Configuration example completed with some issues.")
      sys.exit(0)  # Still exit successfully as issues are expected in demo

  except KeyboardInterrupt:
    print("\n\n⏹️  Example interrupted by user.")
    sys.exit(1)
  except Exception as e:
    print(f"\n❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
