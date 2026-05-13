#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    // Initialize z_stream structure
    z_stream stream;
    memset(&stream, 0, sizeof(z_stream));

    // Allocate memory for input and output
    unsigned char *input = (unsigned char *)malloc(size);
    unsigned char *output = (unsigned char *)malloc(size);

    if (input == NULL || output == NULL) {
        free(input);
        free(output);
        return 0;
    }

    // Copy the data to input buffer
    memcpy(input, data, size);

    // Set up the z_stream structure
    stream.next_in = input;
    stream.avail_in = size;
    stream.next_out = output;
    stream.avail_out = size;

    // Initialize the inflate state
    if (inflateInit(&stream) != Z_OK) {
        free(input);
        free(output);
        return 0;
    }

    // Call the function-under-test
    int result = inflateSync(&stream);

    // Clean up
    inflateEnd(&stream);
    free(input);
    free(output);

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

    LLVMFuzzerTestOneInput_147(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
