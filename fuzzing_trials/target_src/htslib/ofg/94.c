#include <stdint.h>
#include <stdlib.h>
#include <htslib/hts.h> // Include the header file for hts_md5_context

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    // Declare and initialize the hts_md5_context pointer
    hts_md5_context *md5_ctx = hts_md5_init();

    // Ensure the context is not NULL
    if (md5_ctx == NULL) {
        return 0;
    }

    // Feed the input data to the MD5 context
    hts_md5_update(md5_ctx, data, size);

    // Call the function-under-test
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

    LLVMFuzzerTestOneInput_94(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
