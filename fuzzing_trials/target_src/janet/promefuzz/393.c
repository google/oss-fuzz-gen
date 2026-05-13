// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_string_equal at string.c:82:5 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_ev_write_string at janet.c:11750:22 in janet.h
// janet_ev_send_string at janet.c:11759:22 in janet.h
// janet_ev_sendto_string at janet.c:11767:22 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static JanetString create_dummy_string(const uint8_t *data, size_t size) {
    return (JanetString)data;
}

static Janet create_janet_from_string(JanetString str) {
    Janet janet;
    janet.pointer = (void *)str;
    return janet;
}

int LLVMFuzzerTestOneInput_393(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare two JanetString objects
    JanetString str1 = create_dummy_string(Data, Size / 2);
    JanetString str2 = create_dummy_string(Data + Size / 2, Size - Size / 2);

    // Fuzz janet_string_equal
    int equal = janet_string_equal(str1, str2);

    // Create a Janet object and attempt to unwrap a string
    Janet janet = create_janet_from_string(str1);
    JanetString unwrapped_str = janet_unwrap_string(janet);

    // Prepare a dummy JanetStream
    JanetStream stream;
    memset(&stream, 0, sizeof(JanetStream));

    // Fuzz janet_ev_write_string
    janet_ev_write_string(&stream, unwrapped_str);

    // Fuzz janet_ev_send_string
    janet_ev_send_string(&stream, unwrapped_str, 0);

    // Prepare a dummy destination
    void *dest = (void *)Data;

    // Fuzz janet_ev_sendto_string
    janet_ev_sendto_string(&stream, unwrapped_str, dest, 0);

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

        LLVMFuzzerTestOneInput_393(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    