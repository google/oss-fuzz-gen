#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/htslib/htslib/hts.h" // Correct path for the header file

int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    unsigned char result[16]; // MD5 hash is 16 bytes
    hts_md5_context *context = hts_md5_init(); // Use pointer and initialization function

    if (context == NULL) {
        return 0; // Handle initialization failure
    }

    // Update the MD5 context with the input data
    if (size > 0) {
        hts_md5_update(context, data, size);
    }

    // Finalize the MD5 hash
    hts_md5_final(result, context);

    // Free the MD5 context
    hts_md5_destroy(context);

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

    LLVMFuzzerTestOneInput_137(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
