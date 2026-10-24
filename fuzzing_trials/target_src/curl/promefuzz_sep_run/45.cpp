// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_mvaprintf at mprintf.c:1143:7 in mprintf.h
// curl_mvsnprintf at mprintf.c:1081:5 in mprintf.h
// curl_mfprintf at mprintf.c:1208:5 in mprintf.h
// curl_mvsprintf at mprintf.c:1218:5 in mprintf.h
// curl_mvprintf at mprintf.c:1225:5 in mprintf.h
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <mprintf.h>

static void fuzz_with_va_list(const char *format, ...) {
    va_list args;

    // Buffer for curl_mvsnprintf and curl_mvsprintf
    char buffer[256];

    // Dummy FILE* for curl_mfprintf
    FILE *dummyFile = fopen("./dummy_file", "w+");
    if (!dummyFile) return;

    // Begin va_list with provided arguments
    va_start(args, format);

    // Test curl_mvaprintf
    char *formattedStr = curl_mvaprintf(format, args);
    if (formattedStr) {
        free(formattedStr);
    }

    // Reset va_list before reuse
    va_end(args);
    va_start(args, format);

    // Test curl_mvsnprintf
    curl_mvsnprintf(buffer, sizeof(buffer), format, args);

    // Reset va_list before reuse
    va_end(args);
    va_start(args, format);

    // Test curl_mfprintf
    curl_mfprintf(dummyFile, format, args);

    // Reset va_list before reuse
    va_end(args);
    va_start(args, format);

    // Test curl_mvsprintf
    curl_mvsprintf(buffer, format, args);

    // Reset va_list before reuse
    va_end(args);
    va_start(args, format);

    // Test curl_mvprintf
    curl_mvprintf(format, args);

    // Clean up
    va_end(args);
    fclose(dummyFile);
}

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least some data

    // Prepare a format string and dummy arguments
    const char *format = "%s %d";
    const char *dummyString = "Test";
    int dummyInt = 123;

    // Invoke the function with a variable argument list
    fuzz_with_va_list(format, dummyString, dummyInt);

    return 0;
}