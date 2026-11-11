#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

// Ensure to include extern "C" if using C++
// extern "C" {

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Initialize the movie object; assuming gf_isom_open_file is a valid way to initialize
    // Note: Replace "some_file.mp4" with a valid file path or method to create a GF_ISOFile
    movie = gf_isom_open_file("some_file.mp4", GF_ISOM_OPEN_READ, NULL);

    if (movie == NULL) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_reset_sample_count(movie);

    // Clean up
    gf_isom_close(movie);

    return 0;
}

// }
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
