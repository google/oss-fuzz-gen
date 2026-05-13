// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_is_int at inttypes.c:172:14 in janet.h
// janet_unwrap_s64 at inttypes.c:116:9 in janet.h
// janet_getnumber at janet.c:4511:1 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <janet.h>

static Janet generate_random_janet(const uint8_t *Data, size_t Size) {
    Janet janet;
    if (Size < 1) return janet_wrap_nil();
    
    switch (Data[0] % 8) {
        case 0: 
            janet = janet_wrap_nil();
            break;
        case 1:
            janet = janet_wrap_boolean(Data[0] % 2);
            break;
        case 2:
            if (Size >= sizeof(double)) {
                double number;
                memcpy(&number, Data, sizeof(double));
                janet = janet_wrap_number(number);
            } else {
                janet = janet_wrap_number(0.0);
            }
            break;
        case 3:
            if (Size >= sizeof(int64_t)) {
                int64_t i64;
                memcpy(&i64, Data, sizeof(int64_t));
                janet = janet_wrap_integer(i64);
            } else {
                janet = janet_wrap_integer(0);
            }
            break;
        default:
            janet = janet_wrap_nil();
            break;
    }
    return janet;
}

int LLVMFuzzerTestOneInput_403(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;
    
    Janet x = generate_random_janet(Data, Size);
    
    // Fuzz janet_type
    JanetType type = janet_type(x);
    
    // Fuzz janet_is_int
    JanetIntType intType = JANET_INT_NONE;
    if (type == JANET_NUMBER) {
        intType = janet_is_int(x);
    }
    
    // Fuzz janet_unwrap_s64
    if (intType != JANET_INT_NONE) {
        int64_t s64 = janet_unwrap_s64(x);
    }
    
    // Fuzz janet_unwrap_integer
    if (intType == JANET_INT_S64) {
        int32_t integer = janet_unwrap_integer(x);
    }
    
    // Fuzz janet_getnumber
    if (type == JANET_NUMBER) {
        double number = janet_getnumber(&x, 0);
    }
    
    // Fuzz janet_unwrap_boolean
    if (type == JANET_BOOLEAN) {
        int boolean = janet_unwrap_boolean(x);
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

        LLVMFuzzerTestOneInput_403(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    