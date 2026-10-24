// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hts_md5_init at md5.c:323:18 in hts.h
// hts_md5_update at md5.c:237:6 in hts.h
// hts_md5_final at md5.c:271:6 in hts.h
// hts_md5_hex at md5.c:380:6 in hts.h
// hts_md5_reset at md5.c:226:6 in hts.h
// hts_md5_update at md5.c:237:6 in hts.h
// hts_md5_final at md5.c:271:6 in hts.h
// hts_md5_hex at md5.c:380:6 in hts.h
// hts_md5_destroy at md5.c:372:6 in hts.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "hts.h"

int LLVMFuzzerTestOneInput_93(const uint8_t *Data, size_t Size) {
    // Initialize MD5 context
    hts_md5_context *ctx = hts_md5_init();
    if (!ctx) return 0;

    // Create a buffer to hold the MD5 digest
    unsigned char digest[16];
    char hex_output[33];

    // Update the MD5 context with the provided data
    hts_md5_update(ctx, Data, Size);

    // Finalize the MD5 computation
    hts_md5_final(digest, ctx);

    // Convert the digest to a hexadecimal string
    hts_md5_hex(hex_output, digest);

    // Reset the context to test reusability
    hts_md5_reset(ctx);

    // Update with the same data again after reset
    hts_md5_update(ctx, Data, Size);

    // Finalize and convert to hex again
    hts_md5_final(digest, ctx);
    hts_md5_hex(hex_output, digest);

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

    LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
