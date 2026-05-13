// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_get_abstract_type at janet.c:34303:26 in janet.h
// janet_abstract_begin at janet.c:1330:7 in janet.h
// janet_abstract_end at janet.c:1338:7 in janet.h
// janet_abstract_begin_threaded at janet.c:1353:7 in janet.h
// janet_abstract_end_threaded at janet.c:1369:7 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <janet.h>

static JanetAbstractType dummyType = {
    "dummyType",
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

int LLVMFuzzerTestOneInput_758(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) {
        return 0;
    }

    // Initialize the Janet VM
    janet_init();

    // Use the first part of Data as a Janet key
    Janet key;
    memcpy(&key, Data, sizeof(Janet));

    // Ensure the key is a valid Janet type that can be used with janet_get_abstract_type
    if (janet_checktype(key, JANET_STRING) || janet_checktype(key, JANET_SYMBOL)) {
        // Fuzz janet_get_abstract_type
        const JanetAbstractType *abstractType = janet_get_abstract_type(key);
    }

    // Fuzz janet_abstract_begin and janet_abstract_end
    if (Size > 0) {
        void *abstractData = janet_abstract_begin(&dummyType, Size);
        if (abstractData) {
            janet_abstract_end(abstractData);
        }

        // Fuzz janet_abstract_head
        if (abstractData) {
            JanetAbstractHead *head = janet_abstract_head(abstractData);
        }
    }

    // Fuzz janet_abstract_begin_threaded and janet_abstract_end_threaded
    if (Size > 0) {
        void *threadedAbstractData = janet_abstract_begin_threaded(&dummyType, Size);
        if (threadedAbstractData) {
            janet_abstract_end_threaded(threadedAbstractData);
        }
    }

    // Deinitialize the Janet VM
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

        LLVMFuzzerTestOneInput_758(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    