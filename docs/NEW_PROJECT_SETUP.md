# Setting Up New Projects for LogicFuzz

This guide explains how to set up **new projects** (non-OSS-Fuzz projects, private repositories, custom codebases) for fuzzing with LogicFuzz.

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Method 1: Manual Setup](#method-1-manual-setup)
- [Method 2: Automated Build Generation](#method-2-automated-build-generation)
- [Method 3: From Existing Codebase](#method-3-from-existing-codebase)
- [Configuration Files](#configuration-files)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

LogicFuzz can test projects beyond OSS-Fuzz's library:
- ✅ **Private repositories** (internal company code)
- ✅ **New open-source projects** (not yet in OSS-Fuzz)
- ✅ **Custom codebases** (proprietary libraries)
- ✅ **Any C/C++ project** with a build system

### What You Need to Provide

1. **OSS-Fuzz Project Structure** (Dockerfile, build.sh, project.yaml)
2. **Benchmark YAML File** (function signatures to test)
3. **Source Code Access** (local path or git repository)

---

## 📦 Prerequisites

```bash
# Ensure you have the base environment set up
cd /path/to/logic-fuzz

# Clone OSS-Fuzz if not already present
git clone https://github.com/google/oss-fuzz

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Quick Start

### Option A: I have an existing OSS-Fuzz-style project

```bash
# 1. Place your project in OSS-Fuzz structure
mkdir -p oss-fuzz/projects/my-project
cp Dockerfile build.sh project.yaml oss-fuzz/projects/my-project/

# 2. Create benchmark YAML
cat > conti-benchmark/my-project.yaml << 'EOF'
"functions":
- "name": "my_function"
  "params":
  - "name": "input"
    "type": "char*"
  - "name": "length"
    "type": "size_t"
  "return_type": "int"
  "signature": "int my_function(const char*, size_t)"
"language": "c"
"project": "my-project"
"target_name": "my_fuzzer"
"target_path": "/src/my-project/fuzzer.c"
EOF

# 3. Run LogicFuzz
python run_logicfuzz.py -y conti-benchmark/my-project.yaml --model gpt-5
```

### Option B: I have a GitHub repository

```bash
# Use automated build generator
echo "https://github.com/your-org/your-project" > projects.txt

python3 -m experimental.build_generator.runner \
  -i projects.txt \
  -o generated-builds \
  -m gpt-5 \
  --oss-fuzz oss-fuzz
```

---

## 📝 Method 1: Manual Setup

### Step 1: Create OSS-Fuzz Project Directory

```bash
# Create project structure
PROJECT_NAME="my-project"
mkdir -p oss-fuzz/projects/$PROJECT_NAME
cd oss-fuzz/projects/$PROJECT_NAME
```

### Step 2: Create Project Files

#### A. `project.yaml` - Project Metadata

```yaml
homepage: "https://github.com/your-org/my-project"
language: c  # or c++, python, java, rust
primary_contact: "your-email@example.com"
main_repo: "https://github.com/your-org/my-project.git"
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
  - undefined
```

#### B. `Dockerfile` - Build Environment

**For C/C++ projects:**

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    make \
    autoconf \
    automake \
    libtool \
    pkg-config

# Clone your project (or COPY for private repos)
RUN git clone --depth 1 https://github.com/your-org/my-project.git $SRC/my-project

# For private repos, use COPY instead:
# COPY . $SRC/my-project/

WORKDIR $SRC/my-project
COPY build.sh $SRC/
```

**For private repositories:**

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y make

# Copy private source code
COPY . $SRC/my-project/
WORKDIR $SRC/my-project

COPY build.sh $SRC/
```

#### C. `build.sh` - Build Script

```bash
#!/bin/bash -eu

cd $SRC/my-project

# Build your project with coverage instrumentation
# Example for CMake projects:
mkdir -p build
cd build
cmake .. \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS"
make -j$(nproc)

# For Makefile projects:
# make CC=$CC CXX=$CXX CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"

# Compile empty fuzzer (LogicFuzz will generate the actual harness)
cat > $SRC/fuzzer.c << 'EOF'
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // LogicFuzz will replace this with generated fuzzer
    return 0;
}
EOF

# Link fuzzer with your library
$CC $CFLAGS -c $SRC/fuzzer.c -o $WORK/fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $WORK/fuzzer.o \
    -o $OUT/my_fuzzer \
    $SRC/my-project/build/libmyproject.a
```

**Key variables provided by OSS-Fuzz:**
- `$SRC`: Source code directory (`/src`)
- `$OUT`: Output directory for fuzzers (`/out`)
- `$WORK`: Temporary working directory (`/work`)
- `$CC`, `$CXX`: Compilers with fuzzing instrumentation
- `$CFLAGS`, `$CXXFLAGS`: Required compilation flags
- `$LIB_FUZZING_ENGINE`: LibFuzzer engine library

### Step 3: Create Benchmark YAML

Create `conti-benchmark/my-project.yaml`:

```yaml
"functions":
- "name": "parse_data"
  "params":
  - "name": "input"
    "type": "const char*"
  - "name": "length"
    "type": "size_t"
  "return_type": "int"
  "signature": "int parse_data(const char*, size_t)"

- "name": "process_buffer"
  "params":
  - "name": "buffer"
    "type": "void*"
  - "name": "size"
    "type": "size_t"
  "return_type": "void"
  "signature": "void process_buffer(void*, size_t)"

"language": "c"
"project": "my-project"
"target_name": "my_fuzzer"
"target_path": "/src/fuzzer.c"
```

**Field descriptions:**
- `functions`: List of functions to generate fuzz targets for
  - `name`: Function name (without namespace/class)
  - `params`: Parameter list with names and types
  - `return_type`: Function return type
  - `signature`: Full function signature
- `language`: Programming language (`c`, `c++`, `java`, `python`, `rust`)
- `project`: OSS-Fuzz project name (must match directory name)
- `target_name`: Fuzzer binary name (will be in `$OUT/`)
- `target_path`: Path to fuzzer source file in container

### Step 4: Test the Build

```bash
# Build the Docker image
cd /path/to/logic-fuzz
python infra/helper.py build_image my-project

# Build fuzzers
python infra/helper.py build_fuzzers my-project

# Check output
ls -lh oss-fuzz/build/out/my-project/
# Should show: my_fuzzer
```

### Step 5: Run LogicFuzz

```bash
# Basic run
python run_logicfuzz.py \
  -y conti-benchmark/my-project.yaml \
  --model gpt-5

# With Fuzz Introspector (recommended)
python run_logicfuzz.py \
  -y conti-benchmark/my-project.yaml \
  --model gpt-5 \
  --num-samples 5 \
  --context \
  -e http://0.0.0.0:8080/api
```

---

## 🤖 Method 2: Automated Build Generation

For projects with standard build systems (CMake, Makefile, Cargo), use the automated build generator.

### Step 1: Prepare Input File

```bash
# Create a file with GitHub repository URLs (one per line)
cat > projects.txt << EOF
https://github.com/your-org/project1
https://github.com/another-org/project2
EOF
```

### Step 2: Run Build Generator

```bash
python3 -m experimental.build_generator.runner \
  -i projects.txt \
  -o generated-builds \
  -m gpt-5 \
  --oss-fuzz oss-fuzz
```

**Parameters:**
- `-i`: Input file with repository URLs
- `-o`: Output directory for generated projects
- `-m`: LLM model to use for generation
- `--oss-fuzz`: Path to OSS-Fuzz clone

### Step 3: Review Generated Projects

```bash
# Generated projects are in:
ls generated-builds/oss-fuzz-projects/

# Each project contains:
# - Dockerfile
# - build.sh
# - project.yaml
# - fuzzer source file
```

### Step 4: Move to OSS-Fuzz

```bash
# Copy generated project to OSS-Fuzz
PROJECT_NAME="your-project"
cp -r generated-builds/oss-fuzz-projects/$PROJECT_NAME \
     oss-fuzz/projects/
```

### Step 5: Create Benchmark YAML

Use the introspector tool to auto-generate benchmark YAML:

```bash
python -m data_prep.introspector $PROJECT_NAME \
  -m 5 \
  -o conti-benchmark/
```

This creates `conti-benchmark/${PROJECT_NAME}.yaml` with top functions to fuzz.

---

## 📂 Method 3: From Existing Codebase

### For Local/Private Codebases

#### Step 1: Prepare Your Source Code

```bash
# Create a working directory
mkdir -p work/my-private-project
cd work/my-private-project

# Copy your source code
cp -r /path/to/your/code/* .
```

#### Step 2: Create Minimal OSS-Fuzz Structure

```bash
mkdir -p oss-fuzz/projects/my-private-project
cd oss-fuzz/projects/my-private-project
```

**Create `Dockerfile` for private code:**

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    your-required-packages

# Copy local source code
COPY . $SRC/my-private-project/

WORKDIR $SRC/my-private-project
COPY build.sh $SRC/
```

**Create `build.sh`:**

```bash
#!/bin/bash -eu

cd $SRC/my-private-project

# Build your project
# Adapt this to your build system:

# For CMake:
cmake . -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX
make -j$(nproc)

# For Makefile:
# make CC=$CC CXX=$CXX

# Create empty fuzzer
echo 'int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }' \
  > fuzzer.c

# Link fuzzer
$CC $CFLAGS -c fuzzer.c -o fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.o \
  -o $OUT/my_fuzzer \
  libmyproject.a
```

**Create `project.yaml`:**

```yaml
homepage: "https://internal-gitlab.company.com/my-project"
language: c++
primary_contact: "dev-team@company.com"
main_repo: "https://internal-gitlab.company.com/my-project.git"
```

#### Step 3: Extract Function Signatures

Manually create `conti-benchmark/my-private-project.yaml`:

```yaml
"functions":
- "name": "critical_parser_function"
  "params":
  - "name": "data"
    "type": "uint8_t*"
  - "name": "len"
    "type": "size_t"
  "return_type": "int"
  "signature": "int critical_parser_function(uint8_t*, size_t)"
"language": "c++"
"project": "my-private-project"
"target_name": "my_fuzzer"
"target_path": "/src/my-private-project/fuzzer.c"
```

**Tips for finding good functions to fuzz:**
- Look for parsing/deserialization functions
- Functions that process external input
- Complex algorithms with edge cases
- Functions with historical bugs

---

## ⚙️ Configuration Files

### Benchmark YAML Structure

```yaml
"functions":
- "name": "function_name"              # Function name (required)
  "params":                            # Parameter list (required)
  - "name": "param_name"               # Parameter name
    "type": "param_type"               # Parameter C/C++ type
  "return_type": "return_type"         # Return type (required)
  "signature": "full_signature"        # Full function signature (required)

"language": "c"                        # Project language (required)
"project": "project_name"              # OSS-Fuzz project name (required)
"target_name": "fuzzer_binary_name"    # Output fuzzer name (optional)
"target_path": "/src/path/to/fuzzer.c" # Fuzzer source path (required)
```

### Advanced YAML Options

```yaml
"functions":
- "name": "complex_function"
  "params":
  - "name": "ctx"
    "type": "struct context*"
  - "name": "flags"
    "type": "unsigned int"
  "return_type": "bool"
  "signature": "bool complex_function(struct context*, unsigned int)"
  # Optional: Add context for better generation
  "description": "Parses input with given flags"
  "header": "parser.h"

"language": "c++"
"project": "my-project"
"target_name": "parser_fuzzer"
"target_path": "/src/my-project/fuzzers/parser_fuzzer.cc"

# Optional: Specify custom build flags
"build_flags":
  - "-DENABLE_FUZZING=ON"
  - "-DCUSTOM_FLAG=1"
```

---

## 🎓 Examples

### Example 1: Simple C Library

**Project:** JSON parser library

```yaml
# conti-benchmark/myjson.yaml
"functions":
- "name": "json_parse"
  "params":
  - "name": "input"
    "type": "const char*"
  "return_type": "json_value*"
  "signature": "json_value* json_parse(const char*)"

- "name": "json_parse_ex"
  "params":
  - "name": "input"
    "type": "const char*"
  - "name": "length"
    "type": "size_t"
  - "name": "settings"
    "type": "json_settings*"
  "return_type": "json_value*"
  "signature": "json_value* json_parse_ex(const char*, size_t, json_settings*)"

"language": "c"
"project": "myjson"
"target_name": "json_fuzzer"
"target_path": "/src/myjson/fuzzer.c"
```

### Example 2: C++ Class Methods

**Project:** Image processing library

```yaml
# conti-benchmark/imglib.yaml
"functions":
- "name": "Image::decode"
  "params":
  - "name": "data"
    "type": "const std::vector<uint8_t>&"
  "return_type": "bool"
  "signature": "bool Image::decode(const std::vector<uint8_t>&)"

- "name": "Filter::apply"
  "params":
  - "name": "img"
    "type": "Image&"
  - "name": "params"
    "type": "const FilterParams&"
  "return_type": "void"
  "signature": "void Filter::apply(Image&, const FilterParams&)"

"language": "c++"
"project": "imglib"
"target_name": "imglib_fuzzer"
"target_path": "/src/imglib/fuzzer.cc"
```

### Example 3: Multi-Function Project

For the complete example, see [`conti-benchmark/conti_test.yaml`](../conti-benchmark/conti_test.yaml):

```yaml
"functions":
- "name": "parse_int_list"
  "params":
  - "name": "s"
    "type": "char*"
  - "name": "n"
    "type": "size_t"
  "return_type": "int"
  "signature": "int parse_int_list(const char*, size_t)"

- "name": "compute_average"
  "params":
  - "name": "values"
    "type": "int*"
  - "name": "count"
    "type": "size_t"
  - "name": "out_avg"
    "type": "double*"
  "return_type": "int"
  "signature": "int compute_average(const int*, size_t, double*)"

"language": "c"
"project": "conti_test"
"target_name": "conti_test_fuzzer"
"target_path": "/src/conti_test/fuzzer.c"
```

---

## 🔧 Troubleshooting

### Build Failures

**Issue:** `Dockerfile` fails to build

```bash
# Debug by running build manually
cd oss-fuzz
python infra/helper.py build_image my-project --verbose

# Check logs for missing dependencies
# Add them to Dockerfile RUN apt-get install -y ...
```

**Issue:** `build.sh` linking errors

```bash
# Verify library is being built
docker run -it gcr.io/oss-fuzz/my-project /bin/bash
cd $SRC/my-project
# Run build commands manually to debug
```

### YAML Validation Errors

**Issue:** Function signature parsing fails

```python
# Test YAML syntax
python -c "
import yaml
with open('conti-benchmark/my-project.yaml') as f:
    config = yaml.safe_load(f)
    print(config)
"
```

**Common YAML mistakes:**
- Missing quotes around strings with special chars
- Incorrect indentation (use spaces, not tabs)
- Forgetting colons after keys

### LogicFuzz Generation Issues

**Issue:** No fuzz targets generated

```bash
# Check if project builds successfully
python infra/helper.py build_fuzzers my-project

# Verify fuzzer binary exists
ls oss-fuzz/build/out/my-project/

# Enable debug logging
python run_logicfuzz.py \
  -y conti-benchmark/my-project.yaml \
  --model gpt-5 \
  --log-level debug
```

**Issue:** Generated fuzzer doesn't compile

- Check function signatures match exactly (case-sensitive)
- Verify all required headers are available
- Ensure function is exported/visible in library

### Fuzz Introspector Integration

**Issue:** Cannot connect to FI server

```bash
# Verify FI server is running
curl http://0.0.0.0:8080

# Check if your project is in the database
curl http://0.0.0.0:8080/api/projects

# Rebuild FI database if needed
cd fuzz-introspector/tools/web-fuzzing-introspection
python main.py --rebuild
```

---

## 📚 Additional Resources

### Related Documentation

- [Main README](../README.md) - LogicFuzz overview
- [Usage Guide](../Usage.md) - OSS-Fuzz project quick setup
- [Data Preparation](../data_prep/README.md) - Benchmark YAML generation

### OSS-Fuzz Resources

- [OSS-Fuzz Documentation](https://google.github.io/oss-fuzz/)
- [New Project Guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/)
- [Project Examples](https://github.com/google/oss-fuzz/tree/master/projects)

### Build System Examples

For reference, check existing fuzzer build scripts in `fuzzer_build_script/`:
- [`mosh`](../fuzzer_build_script/mosh) - CMake project
- [`bluez`](../fuzzer_build_script/bluez) - Autotools project
- [`libraw`](../fuzzer_build_script/libraw) - Custom Makefile

---

## 💡 Best Practices

### 1. Choose Good Fuzzing Targets

✅ **Good targets:**
- Parsing functions (JSON, XML, binary formats)
- Decompression/decoders
- Network protocol handlers
- File format processors
- Complex algorithms with branches

❌ **Poor targets:**
- Simple getters/setters
- UI rendering functions
- Database queries (without sanitization)
- Functions requiring complex setup

### 2. Start Simple

```bash
# Begin with 1-2 functions
python run_logicfuzz.py \
  -y conti-benchmark/my-project.yaml \
  -f specific_function \
  --model gpt-5

# Scale up after validation
python run_logicfuzz.py \
  -y conti-benchmark/my-project.yaml \
  --model gpt-5 \
  --num-samples 10
```

### 3. Iterate on Signatures

If generation fails, simplify function signatures:

```yaml
# Instead of complex types:
"signature": "int parse(std::shared_ptr<Context> ctx, const Config& cfg)"

# Start with simpler version:
"signature": "int parse(void* ctx, void* cfg)"
```

### 4. Leverage Existing Fuzzers

If your project has existing fuzzers:

```bash
# Copy as templates
cp existing_fuzzer.c oss-fuzz/projects/my-project/
# Reference in target_path
```

---

## 🎯 Next Steps

1. ✅ Set up OSS-Fuzz project structure
2. ✅ Create benchmark YAML file
3. ✅ Test build locally
4. ✅ Run LogicFuzz generation
5. ✅ Evaluate coverage and fix build errors
6. ✅ Iterate and expand to more functions

**Need help?** Check the [troubleshooting section](#troubleshooting) or file an issue!

