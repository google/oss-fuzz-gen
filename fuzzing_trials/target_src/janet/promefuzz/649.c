// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_current_fiber at fiber.c:446:13 in janet.h
// janet_addtimeout at janet.c:9521:6 in janet.h
// janet_current_fiber at fiber.c:446:13 in janet.h
// janet_sleep_await at janet.c:12093:22 in janet.h
// janet_current_fiber at fiber.c:446:13 in janet.h
// janet_addtimeout_nil at janet.c:9534:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_wrap_number(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return;
    double x;
    memcpy(&x, Data, sizeof(double));
    Janet wrapped_number = janet_wrap_number(x);
    // Optionally, check the wrapped_number or use it in further API calls
}

static void fuzz_janet_addtimeout(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return;
    double sec;
    memcpy(&sec, Data, sizeof(double));

    // Ensure the Janet environment is properly initialized
    JanetFiber *fiber = janet_current_fiber();
    if (fiber != NULL) {
        janet_addtimeout(sec);
    }
}

static void fuzz_janet_sleep_await(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return;
    double sec;
    memcpy(&sec, Data, sizeof(double));

    // Ensure the Janet environment is properly initialized
    JanetFiber *fiber = janet_current_fiber();
    if (fiber != NULL) {
        janet_sleep_await(sec);
    }
}

static void fuzz_janet_addtimeout_nil(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return;
    double sec;
    memcpy(&sec, Data, sizeof(double));

    // Ensure the Janet environment is properly initialized
    JanetFiber *fiber = janet_current_fiber();
    if (fiber != NULL) {
        janet_addtimeout_nil(sec);
    }
}

int LLVMFuzzerTestOneInput_649(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return 0;

    // Initialize Janet runtime if needed
    janet_init();

    fuzz_janet_wrap_number(Data, Size);
    fuzz_janet_addtimeout(Data, Size);
    fuzz_janet_sleep_await(Data, Size);
    fuzz_janet_addtimeout_nil(Data, Size);

    // Cleanup Janet runtime
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

        LLVMFuzzerTestOneInput_649(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    