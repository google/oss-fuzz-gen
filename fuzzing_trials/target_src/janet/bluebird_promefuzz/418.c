#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static Janet create_random_janet(const uint8_t *Data, size_t Size, size_t *offset) {
    Janet x;
    if (*offset + sizeof(uint64_t) <= Size) {
        x.u64 = *(uint64_t *)(Data + *offset);
        *offset += sizeof(uint64_t);
    } else {
        x.u64 = 0;
    }
    return x;
}

int LLVMFuzzerTestOneInput_418(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    // Initialize Janet VM
    janet_init();

    size_t offset = 0;
    Janet x = create_random_janet(Data, Size, &offset);

    int result1 = janet_checkint64(x);
    int result2 = janet_checkint(x);
    int result3 = janet_checkuint(x);
    int result4 = janet_checksize(x);

    Janet argv[10];
    for (int i = 0; i < 10 && offset + sizeof(uint64_t) <= Size; i++) {
        argv[i] = create_random_janet(Data, Size, &offset);
    }

    if (offset + sizeof(int32_t) <= Size) {
        int32_t n = *(int32_t *)(Data + offset) % 10;
        offset += sizeof(int32_t);

        if (n >= 0 && n < 10) {
            if (janet_checkint(argv[n])) {
                double numberResult = janet_getnumber(argv, n);
            }
            if (janet_checkint(argv[n]) && janet_checkuint(argv[n])) {
                int32_t natResult = janet_getnat(argv, n);
            }
        }
    }

    // Cleanup Janet VM
    janet_deinit();

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_418(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
