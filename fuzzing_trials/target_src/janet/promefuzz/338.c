// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_abstract at janet.c:1343:7 in janet.h
// janet_abstract at janet.c:1343:7 in janet.h
// janet_getabstract at janet.c:4754:7 in janet.h
// janet_abstract_incref at janet.c:1488:9 in janet.h
// janet_abstract_decref at janet.c:1492:9 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <janet.h>

static const JanetAbstractType dummyType = {
    "dummyType",
    NULL, // gc
    NULL, // gcmark
    NULL, // get
    NULL, // put
    NULL, // marshal
    NULL, // unmarshal
    NULL, // tostring
    NULL, // compare
    NULL, // hash
    NULL, // next
    NULL, // call
    NULL, // length
    NULL, // bytes
    NULL  // gcperthread
};

static void setup_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_338(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + sizeof(int32_t)) {
        return 0;
    }

    setup_dummy_file(Data, Size);

    janet_init(); // Initialize Janet environment

    Janet *argv = malloc(2 * sizeof(Janet));
    if (!argv) {
        janet_deinit();
        return 0;
    }

    argv[0] = janet_wrap_abstract(janet_abstract(&dummyType, sizeof(int)));
    argv[1] = janet_wrap_abstract(janet_abstract(&dummyType, sizeof(int)));

    int32_t index = *((int32_t *)(Data + Size - sizeof(int32_t)));
    index = index % 2; // Ensure index is within bounds
    if (index < 0) index += 2; // Correct negative index

    void *abstract = NULL;
    if (index >= 0 && index < 2) {
        abstract = janet_getabstract(argv, index, &dummyType);
        if (abstract) {
            janet_abstract_incref(abstract);
            janet_abstract_decref(abstract);
        }
    }

    free(argv); // Free allocated memory
    janet_deinit(); // Deinitialize Janet environment

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

        LLVMFuzzerTestOneInput_338(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    