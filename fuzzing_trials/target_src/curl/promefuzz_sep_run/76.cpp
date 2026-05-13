// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_mfprintf at mprintf.c:1208:5 in mprintf.h
// curl_msnprintf at mprintf.c:1106:5 in mprintf.h
// curl_maprintf at mprintf.c:1161:7 in mprintf.h
// curl_msprintf at mprintf.c:1179:5 in mprintf.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdarg>
#include "mprintf.h"

static void fuzz_curl_mfprintf(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "w");
    if (!file) return;

    // Ensure null-termination for the format string
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0');

    curl_mfprintf(file, "%s", format.c_str());

    fclose(file);
}

static void fuzz_curl_msnprintf(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    char buffer[256];
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0');

    curl_msnprintf(buffer, sizeof(buffer), "%s", format.c_str());
}

static void fuzz_curl_maprintf(const uint8_t *Data, size_t Size) {
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0');

    char *result = curl_maprintf("%s", format.c_str());
    if (result) {
        free(result);
    }
}

static void fuzz_curl_mvsprintf(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    char buffer[256];
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0');

    va_list args;
    // Since we cannot use va_start with fixed arguments in this context,
    // we will skip this function in this fuzzing setup.
}

static void fuzz_curl_msprintf(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    char buffer[256];
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0');

    curl_msprintf(buffer, "%s", format.c_str());
}

static void fuzz_curl_mvfprintf(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "w");
    if (!file) return;

    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0');

    va_list args;
    // Since we cannot use va_start with fixed arguments in this context,
    // we will skip this function in this fuzzing setup.

    fclose(file);
}

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size) {
    fuzz_curl_mfprintf(Data, Size);
    fuzz_curl_msnprintf(Data, Size);
    fuzz_curl_maprintf(Data, Size);
    // fuzz_curl_mvsprintf(Data, Size); // Skipped due to va_list issue
    fuzz_curl_msprintf(Data, Size);
    // fuzz_curl_mvfprintf(Data, Size); // Skipped due to va_list issue
    return 0;
}