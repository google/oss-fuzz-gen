#include <stdint.h>
#include <stddef.h>
#include "/src/hoextdown/src/document.h" // Correct path for the header file
#include "/src/hoextdown/src/hash.h"    // Include the header file for hoedown_hash

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Ensure size is non-zero to avoid passing zero to hoedown_hash_new
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test with the size parameter
    hoedown_hash *hash = hoedown_hash_new(size);

    // Assuming there is a function to free or clean up hoedown_hash
    // Uncomment if such a function exists
    // hoedown_hash_free(hash);

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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
