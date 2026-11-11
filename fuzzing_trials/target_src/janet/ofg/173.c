#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern Janet janet_cfun_stream_chunk(int32_t, Janet *);

int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for at least one Janet argument
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Prepare parameters for janet_cfun_stream_chunk
    int32_t arg1 = (int32_t)(data[0]); // Use the first byte as int32_t
    Janet arg2 = janet_wrap_number((double)arg1); // Wrap it as a Janet number

    // Call the function-under-test
    Janet result = janet_cfun_stream_chunk(arg1, &arg2);

    // Clean up Janet VM
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_173(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
