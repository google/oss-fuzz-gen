// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_current_fiber at fiber.c:446:13 in janet.h
// janet_addtimeout_nil at janet.c:9534:6 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_rng_double at janet.c:20232:8 in janet.h
// janet_sleep_await at janet.c:12093:22 in janet.h
// janet_wrap_number_safe at janet.c:37674:7 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <math.h>
#include "janet.h"

static double extract_double(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return 0.0;
    double value;
    memcpy(&value, Data, sizeof(double));
    return value;
}

static void initialize_rng(JanetRNG *rng, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetRNG)) return;
    memcpy(rng, Data, sizeof(JanetRNG));
}

int LLVMFuzzerTestOneInput_635(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return 0;

    // Initialize the Janet environment
    janet_init();

    double sec = extract_double(Data, Size);

    // Ensure there's a current fiber to avoid segfault
    JanetFiber *fiber = janet_current_fiber();
    if (fiber != NULL) {
        janet_addtimeout_nil(sec);
    }

    Janet janet_value = janet_wrap_number(sec);
    (void)janet_value; // Use value to avoid unused variable warning

    JanetRNG rng;
    initialize_rng(&rng, Data, Size);
    double random_value = janet_rng_double(&rng);
    (void)random_value; // Use value to avoid unused variable warning

    if (fiber != NULL) {
        janet_sleep_await(sec);
    }

    Janet safe_janet_value = janet_wrap_number_safe(sec);
    (void)safe_janet_value; // Use value to avoid unused variable warning

    // Cleanup the Janet environment
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

        LLVMFuzzerTestOneInput_635(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    