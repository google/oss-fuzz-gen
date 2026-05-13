// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_wrap_number_safe at janet.c:37674:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_optnumber at janet.c:4526:1 in janet.h
// janet_getnumber at janet.c:4511:1 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static double get_double_from_data(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return 0.0;
    double value;
    memcpy(&value, Data, sizeof(double));
    return value;
}

static int32_t get_int32_from_data(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return 0;
    int32_t value;
    memcpy(&value, Data, sizeof(int32_t));
    return value;
}

int LLVMFuzzerTestOneInput_604(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double) + sizeof(int32_t)) return 0;

    double input_double = get_double_from_data(Data, Size);
    Janet janet_value = janet_nanbox_from_double(input_double);
    double unwrapped_value = janet_unwrap_number(janet_value);

    Janet wrapped_value = janet_wrap_number(input_double);
    double wrapped_unwrapped_value = janet_unwrap_number(wrapped_value);

    Janet safe_wrapped_value = janet_wrap_number_safe(input_double);
    double safe_wrapped_unwrapped_value = janet_unwrap_number(safe_wrapped_value);

    Janet argv[3] = {janet_wrap_number(1.1), janet_wrap_number(2.2), janet_wrap_number(3.3)};
    int32_t argc = 3;
    if (argc <= 0) return 0; // Prevent division by zero
    int32_t index = abs(get_int32_from_data(Data + sizeof(double), Size - sizeof(double))) % argc;
    double default_value = 0.0;

    if (index >= 0 && index < argc) {
        double optnumber_value = janet_optnumber(argv, argc, index, default_value);
        double getnumber_value = janet_getnumber(argv, index);
        (void)optnumber_value;
        (void)getnumber_value;
    }

    (void)unwrapped_value;
    (void)wrapped_unwrapped_value;
    (void)safe_wrapped_unwrapped_value;

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

        LLVMFuzzerTestOneInput_604(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    