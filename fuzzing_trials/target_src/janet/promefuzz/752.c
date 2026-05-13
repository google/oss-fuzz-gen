// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_scan_uint64 at strtod.c:486:5 in janet.h
// janet_scan_number at strtod.c:395:5 in janet.h
// janet_scan_number_base at strtod.c:252:5 in janet.h
// janet_scan_numeric at strtod.c:500:5 in janet.h
// janet_scan_int64 at strtod.c:466:5 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet() {
    static int janet_initialized = 0;
    if (!janet_initialized) {
        janet_init();
        janet_initialized = 1;
    }
}

static void fuzz_janet_scan_uint64(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        uint64_t out;
        janet_scan_uint64(Data, (int32_t)Size, &out);
    }
}

static void fuzz_janet_scan_number(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        double out;
        janet_scan_number(Data, (int32_t)Size, &out);
    }
}

static void fuzz_janet_scan_number_base(const uint8_t *Data, size_t Size) {
    if (Size > 1) {
        double out;
        int32_t base = Data[0] % 36 + 1; // Base between 1 and 36
        janet_scan_number_base(Data + 1, (int32_t)(Size - 1), base, &out);
    }
}

static void fuzz_janet_scan_numeric(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        Janet out;
        janet_scan_numeric(Data, (int32_t)Size, &out);
    }
}

static void fuzz_janet_scan_int64(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        int64_t out;
        janet_scan_int64(Data, (int32_t)Size, &out);
    }
}

int LLVMFuzzerTestOneInput_752(const uint8_t *Data, size_t Size) {
    initialize_janet();
    fuzz_janet_scan_uint64(Data, Size);
    fuzz_janet_scan_number(Data, Size);
    fuzz_janet_scan_number_base(Data, Size);
    fuzz_janet_scan_numeric(Data, Size);
    fuzz_janet_scan_int64(Data, Size);
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

        LLVMFuzzerTestOneInput_752(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    