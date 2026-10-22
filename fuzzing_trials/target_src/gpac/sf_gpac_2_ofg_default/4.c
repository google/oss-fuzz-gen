#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>

// Assuming these are defined in the GPAC library, but we define them here for the sake of the example.
#define GF_ISOM_BOX_TYPE_FTYP 0x66747970 // 'ftyp' in ASCII

struct __tag_isom {
    size_t movie_size;
    uint32_t file_type;
    // Add other necessary fields here if known
};

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    u64 top_box_start;

    // Ensure that the size is sufficient for initialization
    if (size < sizeof(GF_ISOFile) + sizeof(u64)) {
        return 0;
    }

    // Allocate memory for the GF_ISOFile structure
    movie = (GF_ISOFile *)malloc(sizeof(GF_ISOFile));
    if (movie == NULL) {
        return 0;
    }

    // Initialize the GF_ISOFile structure with some data
    memset(movie, 0, sizeof(GF_ISOFile)); // Ensure all fields are zeroed out
    movie->movie_size = size;
    movie->file_type = GF_ISOM_BOX_TYPE_FTYP;

    // Initialize top_box_start with some value from the input data
    top_box_start = *((u64 *)(data));

    // Check if top_box_start is within a valid range to prevent overflow
    if (top_box_start >= size) {
        free(movie);
        return 0;
    }

    // Call the function-under-test
    gf_isom_reset_data_offset(movie, &top_box_start);

    // Free the allocated memory
    free(movie);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
