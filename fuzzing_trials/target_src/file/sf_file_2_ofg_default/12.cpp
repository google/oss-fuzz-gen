#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <magic.h>

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, data, size);

    // Use the result in some way to avoid compiler optimizations
    if (result != NULL) {
        volatile size_t result_len = strlen(result);
        (void)result_len;

        // Additional logic to utilize the result and increase code coverage
        if (strstr(result, "text") != NULL) {
            // Simulate some processing based on the result content
            volatile int dummy = 0;
            dummy++;
        } else if (strstr(result, "image") != NULL) {
            // Additional branch to increase code coverage
            volatile int dummy = 0;
            dummy += 2;
        } else if (strstr(result, "audio") != NULL) {
            // Another branch to increase code coverage
            volatile int dummy = 0;
            dummy += 3;
        } else {
            // Handle other types to further increase code coverage
            volatile int dummy = 0;
            dummy += 4;
        }
    }

    magic_close(magic);
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
