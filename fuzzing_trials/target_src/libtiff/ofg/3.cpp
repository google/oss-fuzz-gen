#include <tiffio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the function-under-test
    if (size < sizeof(uint32_t) + 2 * sizeof(tmsize_t)) {
        return 0;
    }

    // Initialize TIFF structure
    TIFF *tiff = TIFFOpen("/dev/null", "w");
    if (tiff == NULL) {
        return 0;
    }

    // Extract parameters from the input data
    uint32_t read_offset = *(const uint32_t *)data;
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);

    tmsize_t read_size = *(const tmsize_t *)data;
    data += sizeof(tmsize_t);
    size -= sizeof(tmsize_t);

    tmsize_t buffer_size = *(const tmsize_t *)data;
    data += sizeof(tmsize_t);
    size -= sizeof(tmsize_t);

    // Create buffers for reading and user buffer
    void *read_buffer = malloc(read_size);
    void *user_buffer = malloc(buffer_size);

    if (read_buffer == NULL || user_buffer == NULL) {
        free(read_buffer);
        free(user_buffer);
        TIFFClose(tiff);
        return 0;
    }

    // Copy remaining data into the user buffer
    memcpy(user_buffer, data, size < buffer_size ? size : buffer_size);

    // Call the function-under-test
    TIFFReadFromUserBuffer(tiff, read_offset, read_buffer, read_size, user_buffer, buffer_size);

    // Clean up
    free(read_buffer);
    free(user_buffer);
    TIFFClose(tiff);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
