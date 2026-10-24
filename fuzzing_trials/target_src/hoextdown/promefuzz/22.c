// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_realloc at buffer.c:35:1 in buffer.h
// hoedown_buffer_init at buffer.c:48:1 in buffer.h
// hoedown_buffer_putf at buffer.c:150:1 in buffer.h
// hoedown_buffer_init at buffer.c:48:1 in buffer.h
// hoedown_buffer_putc at buffer.c:138:1 in buffer.h
// hoedown_buffer_init at buffer.c:48:1 in buffer.h
// hoedown_buffer_put at buffer.c:120:1 in buffer.h
// hoedown_buffer_slurp at buffer.c:210:1 in buffer.h
// hoedown_buffer_init at buffer.c:48:1 in buffer.h
// hoedown_buffer_put at buffer.c:120:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"

static void *custom_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

static void custom_free(void *ptr) {
    free(ptr);
}

static void fuzz_hoedown_realloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;

    size_t new_size = *((size_t *)Data);
    if (new_size == 0) return; // Prevent zero-size allocation

    void *ptr = hoedown_realloc(NULL, new_size);
    if (ptr) {
        free(ptr);
    }
}

static void fuzz_hoedown_buffer_putf(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return;
    fwrite(Data, 1, Size, file);
    fclose(file);

    file = fopen("./dummy_file", "rb");
    if (!file) return;

    hoedown_buffer buf;
    hoedown_buffer_init(&buf, 8, custom_realloc, custom_free, custom_free);

    hoedown_buffer_putf(&buf, file);

    fclose(file);
    buf.data_free(buf.data);
}

static void fuzz_hoedown_buffer_putc(const uint8_t *Data, size_t Size) {
    if (Size == 0) return;

    hoedown_buffer buf;
    hoedown_buffer_init(&buf, 8, custom_realloc, custom_free, custom_free);

    for (size_t i = 0; i < Size; i++) {
        hoedown_buffer_putc(&buf, Data[i]);
    }

    buf.data_free(buf.data);
}

static void fuzz_hoedown_buffer_slurp(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;

    hoedown_buffer buf;
    hoedown_buffer_init(&buf, 8, custom_realloc, custom_free, custom_free);

    hoedown_buffer_put(&buf, Data, Size);

    size_t slurp_size = *((size_t *)Data) % (buf.size + 1);
    hoedown_buffer_slurp(&buf, slurp_size);

    buf.data_free(buf.data);
}

static void fuzz_hoedown_buffer_put(const uint8_t *Data, size_t Size) {
    hoedown_buffer buf;
    hoedown_buffer_init(&buf, 8, custom_realloc, custom_free, custom_free);

    hoedown_buffer_put(&buf, Data, Size);

    buf.data_free(buf.data);
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    fuzz_hoedown_realloc(Data, Size);
    fuzz_hoedown_buffer_putf(Data, Size);
    fuzz_hoedown_buffer_putc(Data, Size);
    fuzz_hoedown_buffer_slurp(Data, Size);
    fuzz_hoedown_buffer_put(Data, Size);

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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    