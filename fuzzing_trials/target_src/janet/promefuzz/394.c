// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_getfile at janet.c:18322:7 in janet.h
// janet_cfun_stream_close at janet.c:12189:1 in janet.h
// janet_cfun_stream_chunk at janet.c:12221:1 in janet.h
// janet_cfun_stream_read at janet.c:12198:1 in janet.h
// janet_cfun_stream_write at janet.c:12235:1 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static FILE *create_dummy_file() {
    FILE *file = fopen("./dummy_file", "w+");
    if (file) {
        fputs("dummy data", file);
        rewind(file);
    }
    return file;
}

int LLVMFuzzerTestOneInput_394(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return 0;

    // Prepare a dummy Janet array
    Janet argv[2];
    int32_t index = Data[0] % 2; // Choose between 0 and 1
    int32_t flags = 0;

    // Create a dummy file and set it in the Janet array
    FILE *dummy_file = create_dummy_file();
    if (!dummy_file) return 0;

    argv[0].pointer = (void *)dummy_file;
    argv[1].u64 = *((uint64_t *)(Data + 1));

    // Fuzz janet_getfile
    FILE *file = janet_getfile(argv, index, &flags);
    if (file) fclose(file);

    // Fuzz janet_cfun_stream_close
    janet_cfun_stream_close(1, argv);

    // Fuzz janet_cfun_stream_chunk
    janet_cfun_stream_chunk(1, argv);

    // Fuzz janet_cfun_stream_read
    janet_cfun_stream_read(1, argv);

    // Fuzz janet_cfun_stream_write
    janet_cfun_stream_write(1, argv);

    // Clean up
    fclose(dummy_file);
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

        LLVMFuzzerTestOneInput_394(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    