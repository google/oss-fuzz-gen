#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    GF_ISOStorageMode storageMode;

    // Ensure size is sufficient to extract a GF_ISOStorageMode value
    if (size < sizeof(GF_ISOStorageMode)) {
        return 0;
    }

    // Initialize storageMode from the input data
    storageMode = *(GF_ISOStorageMode *)data;

    // Create a dummy GF_ISOFile structure for testing
    movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (movie == NULL) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_set_storage_mode(movie, storageMode);

    // Clean up
    gf_isom_close(movie);

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

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
