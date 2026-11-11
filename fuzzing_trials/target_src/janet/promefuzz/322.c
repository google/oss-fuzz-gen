// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_channel_make_threaded at janet.c:10026:15 in janet.h
// janet_channel_make at janet.c:10019:15 in janet.h
// janet_channel_give at janet.c:10011:5 in janet.h
// janet_channel_take at janet.c:10015:5 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "janet.h"

static JanetChannel *create_channel(uint32_t limit, int threaded) {
    if (threaded) {
        return janet_channel_make_threaded(limit);
    }
    return janet_channel_make(limit);
}

static void test_channel_operations(JanetChannel *channel, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;

    Janet value;
    memcpy(&value, Data, sizeof(Janet));
    Data += sizeof(Janet);
    Size -= sizeof(Janet);

    // Ensure the Janet value is properly initialized
    value.u64 = value.u64 & 0xFFFFFFFF; // Limit the value to a reasonable range

    janet_channel_give(channel, value);

    Janet out;
    janet_channel_take(channel, &out);
}

int LLVMFuzzerTestOneInput_322(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return 0;

    janet_init();

    uint32_t limit;
    memcpy(&limit, Data, sizeof(uint32_t));
    limit = limit > INT32_MAX ? INT32_MAX : limit;
    Data += sizeof(uint32_t);
    Size -= sizeof(uint32_t);

    int threaded = (Size > 0) ? (Data[0] % 2) : 0;
    if (Size > 0) {
        Data++;
        Size--;
    }

    JanetChannel *channel = create_channel(limit, threaded);
    if (channel) {
        test_channel_operations(channel, Data, Size);
    }

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

        LLVMFuzzerTestOneInput_322(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    