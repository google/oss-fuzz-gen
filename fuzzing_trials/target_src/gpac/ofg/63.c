#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Initialize the GF_ISOFile structure
    GF_ISOFile *movie = gf_isom_open(NULL, GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Ensure the size is large enough for trackNumber and stsd_data_size
    if (size < sizeof(uint32_t) * 2) {
        gf_isom_close(movie);
        return 0;
    }

    // Extract trackNumber and stsd_data_size from the input data
    uint32_t trackNumber = *((uint32_t *)data);
    uint32_t stsd_data_size = *((uint32_t *)(data + sizeof(uint32_t)));

    // Ensure that the stsd_data_size does not exceed the remaining data size
    if (stsd_data_size > size - sizeof(uint32_t) * 2) {
        gf_isom_close(movie);
        return 0;
    }

    // Set the stsd_data pointer to the appropriate location in the input data
    uint8_t *stsd_data = (uint8_t *)(data + sizeof(uint32_t) * 2);

    // Call the function under test
    gf_isom_set_track_stsd_templates(movie, trackNumber, stsd_data, stsd_data_size);

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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
