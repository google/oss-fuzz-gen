#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    u64 top_box_start_value = 0;
    u64 *top_box_start = &top_box_start_value;

    // Ensure the data is not empty
    if (size == 0) return 0;

    // Use a temporary directory for the third parameter as required by gf_isom_open
    const char *tmp_dir = "/tmp"; // This is a placeholder for an actual temporary directory

    // Open the ISO file from the data in memory
    movie = gf_isom_open(NULL, GF_ISOM_OPEN_READ, tmp_dir);

    // Ensure movie is not NULL
    if (movie == NULL) return 0;

    // Call the function under test
    gf_isom_reset_data_offset(movie, top_box_start);

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
