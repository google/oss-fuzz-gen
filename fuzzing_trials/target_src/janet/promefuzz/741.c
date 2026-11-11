// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_panics at janet.c:4435:6 in janet.h
// janet_length at value.c:641:9 in janet.h
// janet_scan_numeric at strtod.c:500:5 in janet.h
// janet_getstring at janet.c:4516:1 in janet.h
// janet_to_string at janet.c:28692:16 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_panics(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        // Ensure the data is null-terminated for safe string operations
        uint8_t *message = (uint8_t *)malloc(Size + 1);
        if (!message) return;
        memcpy(message, Data, Size);
        message[Size] = '\0';
        janet_panics((JanetString)message);
        free(message);
    }
}

static void fuzz_janet_length(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(Janet)) {
        Janet x;
        memcpy(&x, Data, sizeof(Janet));
        janet_length(x);
    }
}

static void fuzz_janet_scan_numeric(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        Janet out;
        janet_scan_numeric(Data, (int32_t)Size, &out);
    }
}

static void fuzz_janet_string_head(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(JanetStringHead)) {
        JanetString s = (JanetString)Data;
        janet_string_head(s);
    }
}

static void fuzz_janet_getstring(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(Janet) + sizeof(int32_t)) {
        const Janet *argv = (const Janet *)Data;
        int32_t n = *(int32_t *)(Data + sizeof(Janet));
        janet_getstring(argv, n);
    }
}

static void fuzz_janet_to_string(const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(Janet)) {
        Janet x;
        memcpy(&x, Data, sizeof(Janet));
        janet_to_string(x);
    }
}

int LLVMFuzzerTestOneInput_741(const uint8_t *Data, size_t Size) {
    fuzz_janet_panics(Data, Size);
    fuzz_janet_length(Data, Size);
    fuzz_janet_scan_numeric(Data, Size);
    fuzz_janet_string_head(Data, Size);
    fuzz_janet_getstring(Data, Size);
    fuzz_janet_to_string(Data, Size);
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

        LLVMFuzzerTestOneInput_741(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    