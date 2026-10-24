// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_wrap_number_safe at janet.c:37674:7 in janet.h
// janet_optnumber at janet.c:4526:1 in janet.h
// janet_getnumber at janet.c:4511:1 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static double extract_double(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return 0.0;
    double value;
    memcpy(&value, Data, sizeof(double));
    return value;
}

int LLVMFuzzerTestOneInput_144(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double) + sizeof(int32_t) * 2) return 0;

    double input_double = extract_double(Data, Size);
    Janet janet_value = janet_nanbox_from_double(input_double);
    double unwrapped_double = janet_unwrap_number(janet_value);

    janet_value = janet_wrap_number(input_double);
    unwrapped_double = janet_unwrap_number(janet_value);

    janet_value = janet_wrap_number_safe(input_double);
    unwrapped_double = janet_unwrap_number(janet_value);

    Janet argv[3];
    for (int i = 0; i < 3; i++) {
        argv[i] = janet_wrap_number(extract_double(Data + i * sizeof(double), Size - i * sizeof(double)));
    }

    int32_t index = *((int32_t *)(Data + sizeof(double)));
    double default_value = extract_double(Data + sizeof(double) + sizeof(int32_t), Size - sizeof(double) - sizeof(int32_t));

    if (index >= 0 && index < 3) {
        if (janet_checktype(argv[index], JANET_NUMBER)) {
            double optnumber = janet_optnumber(argv, 3, index, default_value);
            double getnumber = janet_getnumber(argv, index);
        }
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

        LLVMFuzzerTestOneInput_144(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    