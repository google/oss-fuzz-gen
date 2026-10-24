// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_getfile at janet.c:18322:7 in janet.h
// janet_makefile at janet.c:18332:7 in janet.h
// janet_unwrapfile at janet.c:18340:7 in janet.h
// janet_getjfile at janet.c:18318:12 in janet.h
// janet_makejfile at janet.c:18328:12 in janet.h
// janet_file_close at janet.c:17826:5 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static FILE *create_dummy_file() {
    FILE *f = fopen("./dummy_file", "w+");
    if (f) {
        fprintf(f, "Dummy data for fuzzing.\n");
        fflush(f);
        fseek(f, 0, SEEK_SET);
    }
    return f;
}

int LLVMFuzzerTestOneInput_250(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) + sizeof(int32_t)) return 0;

    int32_t index = *((int32_t *)Data);
    int32_t flags = 0;
    FILE *file = create_dummy_file();
    if (!file) return 0;

    // Prepare a Janet array with dummy values
    Janet argv[3];
    argv[0].pointer = file;
    argv[1].u64 = 123456789;
    argv[2].number = 3.14159;

    // Ensure index is within bounds
    int32_t safe_index = index % 3;
    if (safe_index < 0) safe_index += 3;

    // Test janet_getfile
    FILE *retrieved_file = janet_getfile(argv, safe_index, &flags);

    // Test janet_makefile
    Janet janet_file = janet_makefile(file, flags);

    // Test janet_unwrapfile
    FILE *unwrapped_file = janet_unwrapfile(janet_file, &flags);

    // Test janet_getjfile
    JanetFile *janet_file_ptr = janet_getjfile(argv, safe_index);

    // Test janet_makejfile
    JanetFile *new_jfile = janet_makejfile(file, flags);

    // Test janet_file_close
    if (new_jfile) {
        janet_file_close(new_jfile);
    }

    // Cleanup
    if (file) fclose(file);
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

        LLVMFuzzerTestOneInput_250(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    