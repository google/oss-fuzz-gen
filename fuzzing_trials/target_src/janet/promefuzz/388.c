// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_stream at janet.c:9207:14 in janet.h
// janet_stream_flags at janet.c:11238:6 in janet.h
// janet_stream_level_triggered at janet.c:10639:6 in janet.h
// janet_stream_edge_triggered at janet.c:10635:6 in janet.h
// janet_stream_close at janet.c:9244:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_stream_ext at janet.c:9193:14 in janet.h
// janet_stream_close at janet.c:9244:6 in janet.h
// janet_stream_close at janet.c:9244:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetStream *create_dummy_stream(const uint8_t *Data, size_t Size) {
    JanetHandle handle = (Size > 0) ? Data[0] : 0;
    uint32_t flags = (Size > 1) ? Data[1] : 0;
    JanetMethod methods = { "dummy", NULL };
    return janet_stream(handle, flags, &methods);
}

static void fuzz_janet_stream_functions(JanetStream *stream, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        uint32_t flags = Data[0];
        janet_stream_flags(stream, flags);
    }
    janet_stream_level_triggered(stream);
    janet_stream_edge_triggered(stream);
    janet_stream_close(stream);
}

int LLVMFuzzerTestOneInput_388(const uint8_t *Data, size_t Size) {
    // Initialize Janet VM
    if (!janet_init()) {
        return 0;
    }

    JanetStream *stream = create_dummy_stream(Data, Size);
    if (!stream) {
        janet_deinit();
        return 0;
    }

    fuzz_janet_stream_functions(stream, Data, Size);

    // Also test janet_stream_ext
    JanetStream *ext_stream = janet_stream_ext(0, 0, NULL, sizeof(JanetStream));
    if (ext_stream) {
        fuzz_janet_stream_functions(ext_stream, Data, Size);
        janet_stream_close(ext_stream);
    }

    janet_stream_close(stream);

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

        LLVMFuzzerTestOneInput_388(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    