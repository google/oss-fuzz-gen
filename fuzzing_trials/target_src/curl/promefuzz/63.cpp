// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_maprintf at mprintf.c:1187:7 in mprintf.h
// curl_free at escape.c:190:6 in curl.h
// curl_mvsprintf at mprintf.c:1244:5 in mprintf.h
// curl_mvprintf at mprintf.c:1251:5 in mprintf.h
// curl_mvaprintf at mprintf.c:1169:7 in mprintf.h
// curl_free at escape.c:190:6 in curl.h
// curl_mprintf at mprintf.c:1224:5 in mprintf.h
// curl_mvfprintf at mprintf.c:1256:5 in mprintf.h
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
#include <curl/mprintf.h>
#include <iostream>

static void fuzz_curl_maprintf(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0'); // Ensure null-termination
    char *result = curl_maprintf(format.c_str(), "test");
    if (result) {
        curl_free(result);
    }
}

static void fuzz_curl_mvsprintf(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    char buffer[256];
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0'); // Ensure null-termination
    va_list args;
    curl_mvsprintf(buffer, format.c_str(), args);
}

static void fuzz_curl_mvprintf(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0'); // Ensure null-termination
    va_list args;
    curl_mvprintf(format.c_str(), args);
}

static void fuzz_curl_mvaprintf(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0'); // Ensure null-termination
    va_list args;
    char *result = curl_mvaprintf(format.c_str(), args);
    if (result) {
        curl_free(result);
    }
}

static void fuzz_curl_mprintf(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0'); // Ensure null-termination
    curl_mprintf(format.c_str(), "test");
}

static void fuzz_curl_mvfprintf(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    FILE *file = fopen("./dummy_file", "w");
    if (!file) return;
    std::string format(reinterpret_cast<const char*>(Data), Size);
    format.push_back('\0'); // Ensure null-termination
    va_list args;
    curl_mvfprintf(file, format.c_str(), args);
    fclose(file);
}

extern "C" int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    fuzz_curl_maprintf(Data, Size);
    fuzz_curl_mvsprintf(Data, Size);
    fuzz_curl_mvprintf(Data, Size);
    fuzz_curl_mvaprintf(Data, Size);
    fuzz_curl_mprintf(Data, Size);
    fuzz_curl_mvfprintf(Data, Size);
    return 0;
}
    #ifdef INC_MAIN
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
    int main(int argc, char *argv[])
    {
        FILE *f;
        uint8_t *data = NULL;
        long size;

        if(argc < 2)
            exit(0);

        f = fopen(argv[1], "rb");
        if(f == NULL)
            exit(0);

        fseek(f, 0, SEEK_END);

        size = ftell(f);
        rewind(f);

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    