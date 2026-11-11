#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "janet.h"

static void fuzz_janet_scan_uint64(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    uint64_t out;
    janet_scan_uint64(Data, (int32_t)Size, &out);
}

static void fuzz_janet_scan_number_base(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    int32_t base = Data[0] % 36 + 1; // Ensuring base is between 1 and 36
    double out;
    janet_scan_number_base(Data + 1, (int32_t)(Size - 1), base, &out);
}

static void fuzz_janet_scan_numeric(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    Janet out;
    janet_scan_numeric(Data, (int32_t)Size, &out);
}

int LLVMFuzzerTestOneInput_629(const uint8_t *Data, size_t Size) {
    // Initialize the Janet VM
    janet_init();

    // Fuzz each target function
    fuzz_janet_scan_uint64(Data, Size);
    fuzz_janet_scan_number_base(Data, Size);
    fuzz_janet_scan_numeric(Data, Size);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_629(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
