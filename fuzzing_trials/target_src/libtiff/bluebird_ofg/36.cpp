#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include <cstdio>
#include "cstdlib"
#include "cstring"
#include <cstdarg>

extern "C" {
    #include "tiffio.h"
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the strings
    if (size < 3) return 0;

    // Allocate memory for the strings and ensure null termination
    size_t part_size = size / 3;
    char *module = (char *)malloc(part_size + 1);
    char *fmt = (char *)malloc(part_size + 1);
    char *dummy = (char *)malloc(part_size + 1);

    if (!module || !fmt || !dummy) {
        free(module);
        free(fmt);
        free(dummy);
        return 0;
    }

    // Copy data into the strings
    memcpy(module, data, part_size);
    module[part_size] = '\0';

    memcpy(fmt, data + part_size, part_size);
    fmt[part_size] = '\0';

    memcpy(dummy, data + 2 * part_size, part_size);
    dummy[part_size] = '\0';

    // thandle_t is typically a pointer or integer type, using a dummy pointer here
    thandle_t handle = reinterpret_cast<thandle_t>(dummy);

    // Call the function-under-test
    // Ensure the fmt string is not empty to avoid undefined behavior
    if (fmt[0] != '\0') {
        TIFFSetWarningHandler([](const char* module, const char* fmt, va_list ap) {
            vfprintf(stderr, fmt, ap);
            fprintf(stderr, "\n");
        });

        // Ensure the module string is not empty to avoid undefined behavior
        if (module[0] != '\0') {
            // Ensure the format string is valid by replacing any '%' with '%%'
            for (size_t i = 0; i < part_size; ++i) {
                if (fmt[i] == '%') {
                    fmt[i] = ' ';
                }
            }
            TIFFWarningExt(handle, module, fmt);
        }
    }

    // Free allocated memory
    free(module);
    free(fmt);
    free(dummy);

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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
