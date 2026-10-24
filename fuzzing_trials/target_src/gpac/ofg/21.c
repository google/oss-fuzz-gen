#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    u32 trackNumber = 1; // Example track number, assuming at least one track exists
    u8 *sample_data;
    u32 data_size;

    // Initialize the movie (GF_ISOFile). Assuming the movie is opened or created elsewhere.
    // For fuzzing, we can simulate opening a new file.
    movie = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);

    if (!movie) {
        return 0; // If movie cannot be opened, exit early
    }

    // Ensure we have some data to work with
    if (size > 0) {
        sample_data = (u8 *)data;
        data_size = (u32)size;
    } else {
        // If size is 0, provide a default data buffer
        static u8 default_data[] = {0x00, 0x01, 0x02, 0x03};
        sample_data = default_data;
        data_size = sizeof(default_data);
    }

    // Call the function under test
    gf_isom_append_sample_data(movie, trackNumber, sample_data, data_size);

    // Close the movie file after operation
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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
