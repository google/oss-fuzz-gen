#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t maxSize) {
  (void)data;
  (void)maxSize;

  return size;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

namespace fs = std::filesystem;

static void run(const fs::path &filePath) {
  std::ifstream file(filePath, std::ios::binary);
  if (!file) {
    std::cerr << "Error opening file: " << filePath << std::endl;
    return;
  }

  file.seekg(0, std::ios::end);
  std::streampos fileSize = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> data(fileSize);
  if (!file.read(reinterpret_cast<char *>(data.data()), fileSize)) {
    std::cerr << "Error reading file: " << filePath << std::endl;
    return;
  }

  static size_t counter;
  std::cout << "Run " << ++counter << ": " << filePath << std::endl;
  LLVMFuzzerTestOneInput(data.data(), data.size());
}

static void readFilesInDirectory(const fs::path &directoryPath) {
  for (const auto &entry : fs::recursive_directory_iterator(directoryPath)) {
    if (fs::is_regular_file(entry)) {
      const auto &filePath = entry.path();
      run(filePath);
    }
  }
}

int main(int argc, char *argv[]) {
  LLVMFuzzerInitialize(&argc, &argv);

  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument[0] == '-') {
      continue;
    }

    const fs::path filePath = argument;

    if (fs::exists(filePath)) {
      if (fs::is_regular_file(filePath)) {
        run(filePath);
      } else if (fs::is_directory(filePath)) {
        readFilesInDirectory(filePath);
      } else {
        std::cerr << "Unknown file type: " << filePath << std::endl;
      }
    } else {
      std::cerr << "File not found: " << filePath << std::endl;
    }
  }

  return 0;
}
