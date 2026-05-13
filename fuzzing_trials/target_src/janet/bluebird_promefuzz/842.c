#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "janet.h"

static Janet random_janet_value(const uint8_t *Data, size_t Size, size_t *index) {
    if (*index >= Size) return janet_wrap_integer(0);
    uint8_t type = Data[(*index)++];
    switch (type % 5) {
        case 0:
            if (*index < Size) {
                return janet_wrap_integer((int32_t)(Data[(*index)++] % 256));
            }
            break;
        case 1:
            if (*index < Size) {
                return janet_wrap_integer((int32_t)(Data[(*index)++] % 256) - 128);
            }
            break;
        case 2:
            if (*index < Size) {
                return janet_wrap_integer((int32_t)(Data[(*index)++] % 256) * 1000);
            }
            break;
        case 3:
            if (*index < Size) {
                return janet_wrap_integer((int32_t)(Data[(*index)++] % 256) / 10);
            }
            break;
        default:
            return janet_wrap_integer(0);
    }
    return janet_wrap_integer(0);
}

int LLVMFuzzerTestOneInput_842(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    janet_init();

    size_t index = 0;

    // Fuzz janet_equals
    Janet x = random_janet_value(Data, Size, &index);
    Janet y = random_janet_value(Data, Size, &index);
    int equals_result = janet_equals(x, y);

    // Fuzz janet_checkint
    int checkint_result = janet_checkint(x);

    // Fuzz janet_tuple_begin
    if (index < Size) {
        int32_t length = (int32_t)(Data[index++] % 256);
        if (length >= 0) {
            Janet *tuple = janet_tuple_begin(length);
            (void)tuple; // Use the tuple if needed
        }
    }

    // Fuzz janet_compare
    int compare_result = janet_compare(x, y);

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

    LLVMFuzzerTestOneInput_842(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
