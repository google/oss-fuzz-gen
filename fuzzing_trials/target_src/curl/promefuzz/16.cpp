// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_maprintf at mprintf.c:1187:7 in mprintf.h
// curl_free at escape.c:190:6 in curl.h
// curl_mvsprintf at mprintf.c:1244:5 in mprintf.h
// curl_mvprintf at mprintf.c:1251:5 in mprintf.h
// curl_msnprintf at mprintf.c:1132:5 in mprintf.h
// curl_mvsnprintf at mprintf.c:1107:5 in mprintf.h
// curl_mprintf at mprintf.c:1224:5 in mprintf.h
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

static void testCurlFunctions(const char *format, ...) {
    va_list args;
    va_start(args, format);

    // Prepare a buffer for the output
    const size_t bufferSize = 256;
    char buffer[bufferSize];

    // Test curl_maprintf
    char *maprintf_result = curl_maprintf(format, args);
    if (maprintf_result) {
        curl_free(maprintf_result);
    }

    // Test curl_mvsprintf
    curl_mvsprintf(buffer, format, args);

    // Test curl_mvprintf
    curl_mvprintf(format, args);

    // Test curl_msnprintf
    curl_msnprintf(buffer, bufferSize, format, args);

    // Test curl_mvsnprintf
    curl_mvsnprintf(buffer, bufferSize, format, args);

    // Test curl_mprintf
    curl_mprintf(format, args);

    va_end(args);
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a format string from the input data
    const size_t formatSize = Size / 2;
    char *format = new char[formatSize + 1];
    std::memcpy(format, Data, formatSize);
    format[formatSize] = '\0';

    // Call the test function with the format string and dummy arguments
    testCurlFunctions(format, 0, 0, 0, 0, 0);

    delete[] format;

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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    