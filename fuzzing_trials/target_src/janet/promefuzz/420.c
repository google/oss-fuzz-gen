// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_get_abstract_type at janet.c:34303:26 in janet.h
// janet_abstract_threaded at janet.c:1374:7 in janet.h
// janet_optabstract at janet.c:4874:7 in janet.h
// janet_register_abstract_type at janet.c:34292:6 in janet.h
// janet_abstract at janet.c:1343:7 in janet.h
// janet_abstract_begin_threaded at janet.c:1353:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static const JanetAbstractType dummy_abstract_type = {
    "dummy",
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

int LLVMFuzzerTestOneInput_420(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) {
        return 0;
    }

    // Prepare a dummy file if needed
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Use a part of the input data as a key for janet_get_abstract_type
    Janet key;
    memcpy(&key, Data, sizeof(Janet));
    const JanetAbstractType *atype = janet_get_abstract_type(key);

    // Ensure atype is non-NULL before proceeding
    if (atype) {
        // Fuzz janet_abstract_threaded
        void *threaded_instance = janet_abstract_threaded(atype, Size);

        // Fuzz janet_optabstract
        JanetAbstract optabstract = janet_optabstract((Janet *)Data, (int32_t)Size, 0, atype, threaded_instance);

        // Fuzz janet_register_abstract_type
        janet_register_abstract_type(atype);

        // Fuzz janet_abstract
        JanetAbstract abstract_instance = janet_abstract(atype, Size);

        // Fuzz janet_abstract_begin_threaded
        void *begin_threaded_instance = janet_abstract_begin_threaded(atype, Size);
    }

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

        LLVMFuzzerTestOneInput_420(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    