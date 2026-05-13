#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/liblouis/liblouis/liblouis.h"
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Ensure there's enough data to read an int
    }

    // Cast the first bytes of data to an integer for log level
    int logLevel = *(reinterpret_cast<const int*>(data));

    // Ensure the log level is within the valid range of the logLevels enum
    if (logLevel < 0 || logLevel >= LOU_LOG_ALL) {
        logLevel = LOU_LOG_ALL - 1; // Default to the highest valid log level
    }

    // Call the function-under-test with the log level
    lou_setLogLevel(static_cast<logLevels>(logLevel));

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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
