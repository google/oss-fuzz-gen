// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_array at janet.c:1562:13 in janet.h
// janet_array_push at janet.c:1620:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_array_pop at janet.c:1631:7 in janet.h
// janet_array_peek at janet.c:1640:7 in janet.h
// janet_array_push at janet.c:1620:6 in janet.h
// janet_array_n at janet.c:1576:13 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_array_pop at janet.c:1631:7 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static JanetArray *create_sample_array(int32_t capacity) {
    JanetArray *array = janet_array(capacity);
    for (int32_t i = 0; i < capacity; i++) {
        Janet element;
        element.i64 = i; // Assigning some integer value
        janet_array_push(array, element);
    }
    return array;
}

int LLVMFuzzerTestOneInput_713(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return 0;

    // Initialize Janet VM
    janet_init();

    // Create a sample JanetArray
    JanetArray *array = create_sample_array(10);

    // Fuzz janet_array_pop
    Janet popped = janet_array_pop(array);

    // Fuzz janet_array_peek
    Janet peeked = janet_array_peek(array);

    // Fuzz janet_array_push
    Janet new_element;
    memcpy(&new_element, Data, sizeof(Janet));
    janet_array_push(array, new_element);

    // Fuzz janet_array_n
    int32_t n = Size / sizeof(Janet);
    JanetArray *new_array = janet_array_n((const Janet *)Data, n);

    // Fuzz janet_unwrap_array
    JanetArray *unwrapped = janet_unwrap_array(new_element);

    // Cleanup
    if (new_array) {
        janet_array_pop(new_array); // Just to ensure some usage
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_713(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    