// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_get at value.c:514:7 in janet.h
// janet_lengthv at value.c:678:7 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

// Ensure Janet is initialized before use
static void initialize_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void setup_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_163(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t) + sizeof(int64_t)) return 0;

    initialize_janet();

    // Prepare a JanetAbstract from the input data
    JanetAbstract abstract = (JanetAbstract)(Data);

    // Wrap the abstract into a Janet value
    Janet wrapped_abstract = janet_wrap_abstract(abstract);

    // Wrap nil into a Janet value
    Janet wrapped_nil = janet_wrap_nil();

    // Prepare a Janet value for data structure and key
    Janet ds;
    Janet key;
    ds.u64 = *((uint64_t *)Data);
    key.i64 = *((int64_t *)(Data + sizeof(uint64_t)));

    // Check if ds is a valid type for janet_get
    if (janet_checktype(ds, JANET_ARRAY) || janet_checktype(ds, JANET_STRING) ||
        janet_checktype(ds, JANET_TUPLE) || janet_checktype(ds, JANET_BUFFER) ||
        janet_checktype(ds, JANET_ABSTRACT)) {
        // Get a value from the data structure using the key
        Janet get_result = janet_get(ds, key);
    }

    // Determine the length of the Janet value
    Janet length_result;
    if (janet_checktype(ds, JANET_ARRAY) || janet_checktype(ds, JANET_STRING) ||
        janet_checktype(ds, JANET_TUPLE) || janet_checktype(ds, JANET_BUFFER)) {
        length_result = janet_lengthv(ds);
    } else {
        length_result = janet_wrap_nil();
    }

    // Unwrap the abstract value from a Janet value
    JanetAbstract unwrapped_abstract = janet_unwrap_abstract(wrapped_abstract);

    // Setup dummy file if needed
    setup_dummy_file(Data, Size);

    // Clean-up if necessary (not much to do here as Janet handles memory management)

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

        LLVMFuzzerTestOneInput_163(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    