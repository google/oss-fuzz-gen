#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/hts.h" // Assuming htslib/hts.h contains the definition for hts_md5_context

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    unsigned char result[16]; // MD5 produces a 16-byte hash
    hts_md5_context *ctx;

    // Initialize the MD5 context
    ctx = hts_md5_init();
    if (ctx == NULL) {
        return 0; // Exit if context initialization fails
    }

    // Simulate processing data with MD5
    hts_md5_update(ctx, data, size);

    // Finalize the MD5 hash
    hts_md5_final(result, ctx);

    // Clean up
    hts_md5_destroy(ctx);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
