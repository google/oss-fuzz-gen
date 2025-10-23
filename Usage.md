# Logic-Fuzz: OSS-Fuzz Project Quick Setup Guide

This repository is designed for quickly creating and testing new OSS-Fuzz projects. It includes standardized templates and automation scripts to help you rapidly integrate new projects into the OSS-Fuzz ecosystem.

## 📁 Project Structure

```
logic-fuzz/
├── work/oss-fuzz/projects/          # OSS-Fuzz project directory
│   └── conti_test/                  # Example project
│       ├── Dockerfile               # Docker build file
│       ├── build.sh                 # Build script
│       ├── project.yaml             # Project configuration
│       └── fuzzer.c                 # Fuzzer source code
├── scripts/run-new-oss-fuzz-project/  # Automation scripts
│   ├── setup.sh                     # Environment setup script
│   └── run-project.sh               # Project run script
├── conti-benchmark/                 # Benchmark configuration
└── README.md                        # This documentation
```

## 🚀 Quick Start

### 1. Create New Project

Create directory structure for new project:

```bash
# Create new project directory
mkdir -p work/oss-fuzz/projects/your-project-name

# Enter project directory
cd work/oss-fuzz/projects/your-project-name
```

### 2. Configure Project Files

#### 📄 **Dockerfile Template**

Create `Dockerfile`:

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder

# Install project dependencies (modify as needed)
RUN apt-get update && apt-get install -y make

# Copy source code to container (change to your project name)
COPY . $SRC/your-project-name/

# Set working directory
WORKDIR $SRC/your-project-name

# Copy build script
COPY build.sh $SRC/
```

#### 🔧 **build.sh Template**

Create `build.sh`:

```bash
#!/bin/bash -eu

# Enter project directory
cd $SRC/your-project-name

# Compile project (modify according to your build system)
make

# Compile fuzzer (change to your fuzzer file name)
$CXX $CXXFLAGS -I./include -c fuzzer.c -o fuzzer.o

# Link and generate final fuzzer executable
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.o build/libyour-library-name.a -o $OUT/your-project-name_fuzzer

# Copy auxiliary files (optional)
if [ -f "your-project-name_fuzzer.dict" ]; then
    cp your-project-name_fuzzer.dict $OUT/
fi

if [ -f "your-project-name_fuzzer.options" ]; then
    cp your-project-name_fuzzer.options $OUT/
fi
```

#### 📋 **project.yaml Template**

Create `project.yaml`:

```yaml
homepage: "https://github.com/your-username/your-project-name"
language: c++  # or c, java, python, etc.
primary_contact: "your-email@example.com"
main_repo: "https://github.com/your-username/your-project-name.git"
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
  - undefined
  - memory
```

#### 🎯 **fuzzer.c Template**

Create basic fuzzer file:

```c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include your project header files
#include "your-header-file.h"

// LibFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Basic input validation
    if (size < 1) {
        return 0;
    }
    
    // Call the function you want to test
    // Example: your_function_name(data, size);
    
    return 0;
}
```

## 🛠️ OSS-Fuzz Standard Conventions

### Environment Variables

OSS-Fuzz provides the following standard environment variables:

| Variable | Path | Purpose |
|----------|------|---------|
| `$SRC` | `/src` | Source code directory |
| `$OUT` | `/out` | Output directory (fuzzer executables) |
| `$WORK` | `/work` | Temporary working directory |
| `$CC` | - | C compiler |
| `$CXX` | - | C++ compiler |
| `$CFLAGS` | - | C compilation flags |
| `$CXXFLAGS` | - | C++ compilation flags |
| `$LIB_FUZZING_ENGINE` | - | Fuzzing engine library |

### Directory Structure Conventions

```
/src/                          # $SRC directory
├── build.sh                   # Build script
├── your-project-name/         # Project source code
│   ├── src/                   # Source files
│   ├── include/               # Header files
│   ├── fuzzer.c               # Fuzzer code
│   ├── Makefile               # Build file
│   └── ...
└── other-dependencies/

/out/                          # $OUT directory
├── your-project-name_fuzzer   # Compiled fuzzer
├── your-project-name_fuzzer.dict      # Dictionary file (optional)
├── your-project-name_fuzzer.options   # Options file (optional)
└── *_seed_corpus.zip          # Seed corpus (optional)
```

## 🧪 Testing and Running

### Local Testing

```bash
# Build Docker image
cd work/oss-fuzz/projects/your-project-name
docker build -t gcr.io/oss-fuzz/your-project-name .

# Run build
docker run --rm -v $(pwd):/src/your-project-name gcr.io/oss-fuzz/your-project-name

# Test fuzzer
docker run --rm -v $(pwd):/out gcr.io/oss-fuzz/your-project-name /out/your-project-name_fuzzer
```

### Using Automation Scripts

```bash
# Setup environment
./scripts/run-new-oss-fuzz-project/setup.sh

# Run project
./scripts/run-new-oss-fuzz-project/run-project.sh your-project-name
```

## 📝 Language-Specific Configurations

### C/C++ Projects

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool
```

### Java Projects

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-jvm
RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.9.5/binaries/apache-maven-3.9.5-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip
ENV MVN $SRC/maven/apache-maven-3.9.5/bin/mvn
```

### Python Projects

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-python
RUN python3 -m pip install --upgrade pip
```

### Rust Projects

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-rust
```

## 🎯 Best Practices

### 1. Fuzzer Design Principles

- **Input Validation**: Always validate input size and format
- **Memory Safety**: Avoid buffer overflows and memory leaks
- **Exception Handling**: Properly handle all possible exception cases
- **Coverage**: Ensure fuzzer can reach different code paths

### 2. Performance Optimization

- **Fast Failure**: Return quickly for invalid inputs
- **Avoid Slow Operations**: Don't execute time-consuming operations in fuzzer
- **Memory Limits**: Control memory usage, avoid OOM

### 3. Debugging Tips

```bash
# Enable verbose logging
export ASAN_OPTIONS="verbosity=1:halt_on_error=1"

# Run single test case
./your-project-name_fuzzer test-file

# Generate coverage report
./your-project-name_fuzzer -runs=0 -dump_coverage=1
```

## 🔧 Common Issues and Solutions

### Build Failures

1. **Check Dependencies**: Ensure all dependencies are installed in Dockerfile
2. **Path Issues**: Verify all paths use correct environment variables
3. **Permission Issues**: Ensure build.sh has execute permissions

### Fuzzer Runtime Issues

1. **Linking Errors**: Check library file paths and linking order
2. **Runtime Errors**: Use AddressSanitizer to debug memory issues
3. **Low Coverage**: Check fuzzer input processing logic

## 📚 Reference Resources

- [OSS-Fuzz Official Documentation](https://google.github.io/oss-fuzz/)
- [LibFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [AddressSanitizer Documentation](https://clang.llvm.org/docs/AddressSanitizer.html)
- [OSS-Fuzz Project Examples](https://github.com/google/oss-fuzz/tree/master/projects)

## 🤝 Contributing

Welcome to submit Issues and Pull Requests to improve this template and documentation!

---

**Note**: Remember to modify the placeholders in the templates according to your specific project requirements (such as `your-project-name`, `your-username`, etc.).