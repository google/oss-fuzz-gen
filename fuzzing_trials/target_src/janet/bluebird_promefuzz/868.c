#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static Janet create_random_janet(const uint8_t *Data, size_t Size, size_t *Index) {
    if (*Index >= Size) return janet_wrap_integer(0);

    uint8_t type = Data[(*Index)++];
    Janet result;
    switch (type % 5) {
        case 0: {
            if (*Index + sizeof(int32_t) <= Size) {
                int32_t num = *(int32_t *)(Data + *Index);
                *Index += sizeof(int32_t);
                result = janet_wrap_integer(num);
            } else {
                result = janet_wrap_integer(0);
            }
            break;
        }
        case 1: {
            result = janet_wrap_integer(0);
            break;
        }
        case 2: {
            result = janet_wrap_integer(1);
            break;
        }
        case 3: {
            if (*Index + sizeof(double) <= Size) {
                double num = *(double *)(Data + *Index);
                *Index += sizeof(double);
                result = janet_wrap_integer((int32_t)num);
            } else {
                result = janet_wrap_integer(0);
            }
            break;
        }
        default:
            result = janet_wrap_integer(0);
            break;
    }
    return result;
}

int LLVMFuzzerTestOneInput_868(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize Janet VM
    janet_init();

    size_t index = 0;
    Janet janet1 = create_random_janet(Data, Size, &index);
    Janet janet2 = create_random_janet(Data, Size, &index);

    // Fuzz janet_length
    if (janet_checktype(janet1, JANET_ARRAY) || 
        janet_checktype(janet1, JANET_STRING) || 
        janet_checktype(janet1, JANET_BUFFER)) {
        int32_t length1 = janet_length(janet1);
    }

    if (janet_checktype(janet2, JANET_ARRAY) || 
        janet_checktype(janet2, JANET_STRING) || 
        janet_checktype(janet2, JANET_BUFFER)) {
        int32_t length2 = janet_length(janet2);
    }

    // Fuzz janet_equals
    int equals = janet_equals(janet1, janet2);

    // Fuzz janet_checkint16
    int checkint16_1 = janet_checkint16(janet1);
    int checkint16_2 = janet_checkint16(janet2);

    // Fuzz janet_checktype
    int checktype1 = janet_checktype(janet1, JANET_NUMBER);
    int checktype2 = janet_checktype(janet2, JANET_NUMBER);

    // Fuzz janet_lengthv
    if (janet_checktype(janet1, JANET_ARRAY) || 
        janet_checktype(janet1, JANET_STRING) || 
        janet_checktype(janet1, JANET_BUFFER)) {
        Janet lengthv1 = janet_lengthv(janet1);
    }

    if (janet_checktype(janet2, JANET_ARRAY) || 
        janet_checktype(janet2, JANET_STRING) || 
        janet_checktype(janet2, JANET_BUFFER)) {
        Janet lengthv2 = janet_lengthv(janet2);
    }

    // Deinitialize Janet VM
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

    LLVMFuzzerTestOneInput_868(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
