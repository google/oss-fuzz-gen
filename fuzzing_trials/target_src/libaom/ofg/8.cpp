#include <stdint.h>
#include <stddef.h>
#include <aom/aom_codec.h>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Initialize variables
    aom_codec_ctx_t codec_ctx;
    int control_id = 0;  // Example control ID
    void *control_data = nullptr;

    // Ensure the data size is sufficient to initialize control_data
    if (size < sizeof(void*)) {
        return 0;
    }

    // Use the first part of data to initialize control_data
    control_data = (void*)data;

    // Call the function-under-test
    aom_codec_err_t result = aom_codec_control(&codec_ctx, control_id, control_data);

    // Use the result if needed, for now, we just return 0
    (void)result;

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
