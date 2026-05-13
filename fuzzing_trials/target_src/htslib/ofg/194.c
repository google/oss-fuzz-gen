#include <stdint.h>
#include <stdlib.h>
#include <htslib/hts.h>  // Include the header for HTS functions

int LLVMFuzzerTestOneInput_194(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for fuzzing
    if (size == 0) {
        return 0;
    }

    // Initialize the MD5 context
    hts_md5_context *md5_ctx = hts_md5_init();
    if (md5_ctx == NULL) {
        return 0;
    }

    // Call the function-under-test
    hts_md5_update(md5_ctx, (const void *)data, (unsigned long)size);

    // Clean up the MD5 context
    hts_md5_destroy(md5_ctx);

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

    LLVMFuzzerTestOneInput_194(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
