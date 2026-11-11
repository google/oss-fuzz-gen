#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static Janet create_random_janet(const uint8_t *Data, size_t Size) {
    Janet janet;
    if (Size >= sizeof(uint64_t)) {
        janet.u64 = *((uint64_t *)Data);
    } else {
        janet.u64 = 0;
    }
    return janet;
}

int LLVMFuzzerTestOneInput_624(const uint8_t *Data, size_t Size) {
    // Initialize Janet VM
    janet_init();

    if (Size < sizeof(int32_t)) {
        janet_deinit();
        return 0;
    }

    int32_t capacity = *((int32_t *)Data);
    Data += sizeof(int32_t);
    Size -= sizeof(int32_t);

    JanetArray *array = janet_array(capacity);

    if (Size >= sizeof(Janet)) {
        Janet element = create_random_janet(Data, Size);
        janet_array_push(array, element);
    }

    Janet last_element = janet_array_peek(array);
    (void)last_element;

    Janet popped_element = janet_array_pop(array);
    (void)popped_element;

    if (Size >= sizeof(Janet)) {
        Janet elements[5];
        for (int i = 0; i < 5 && Size >= sizeof(Janet); i++, Size -= sizeof(Janet), Data += sizeof(Janet)) {
            elements[i] = create_random_janet(Data, Size);
        }
        JanetArray *new_array = janet_array_n(elements, 5);
        janet_array_push(new_array, create_random_janet(Data, Size));
        Janet peeked_element = janet_array_peek(new_array);
        (void)peeked_element;
        Janet popped_element_new = janet_array_pop(new_array);
        (void)popped_element_new;
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

    LLVMFuzzerTestOneInput_624(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
