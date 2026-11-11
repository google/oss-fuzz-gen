// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_register_abstract_type at janet.c:34292:6 in janet.h
// janet_abstract_begin at janet.c:1330:7 in janet.h
// janet_abstract_end at janet.c:1338:7 in janet.h
// janet_abstract at janet.c:1343:7 in janet.h
// janet_abstract_threaded at janet.c:1374:7 in janet.h
// janet_abstract_begin_threaded at janet.c:1353:7 in janet.h
// janet_abstract_end at janet.c:1338:7 in janet.h
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

static JanetAbstractType fuzzAbstractType = {
    "fuzzType",
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

int LLVMFuzzerTestOneInput_302(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAbstractType)) {
        return 0;
    }

    // Initialize Janet environment
    janet_init();

    // Register the abstract type
    janet_register_abstract_type(&fuzzAbstractType);

    // Fuzz janet_abstract_begin
    void *beginAbstract = janet_abstract_begin(&fuzzAbstractType, Size);
    if (beginAbstract) {
        // Fuzz janet_abstract_end
        JanetAbstract endAbstract = janet_abstract_end(beginAbstract);

        // Fuzz janet_abstract
        JanetAbstract abstract = janet_abstract(&fuzzAbstractType, Size);

        // Fuzz janet_abstract_threaded
        void *threadedAbstract = janet_abstract_threaded(&fuzzAbstractType, Size);

        // Fuzz janet_abstract_begin_threaded
        void *beginThreadedAbstract = janet_abstract_begin_threaded(&fuzzAbstractType, Size);
        if (beginThreadedAbstract) {
            janet_abstract_end(beginThreadedAbstract);
        }
    }

    // Cleanup Janet environment
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

        LLVMFuzzerTestOneInput_302(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    