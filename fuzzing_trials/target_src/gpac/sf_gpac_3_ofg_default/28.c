#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    FILE *temp_file = NULL;
    char temp_filename[] = "temp_movie.mp4";

    // Ensure the data size is sufficient to create a mock file structure
    if (size > 0) {
        // Write the data to a temporary file
        temp_file = fopen(temp_filename, "wb");
        if (temp_file == NULL) {
            return 0;
        }

        fwrite(data, 1, size, temp_file);
        fclose(temp_file);

        // Open the movie file using the temporary file
        movie = gf_isom_open(temp_filename, GF_ISOM_OPEN_READ, NULL);

        // Check if the movie is successfully opened
        if (movie != NULL) {
            // Call the function under test
            gf_isom_close(movie);
        }

        // Remove the temporary file
        remove(temp_filename);
    }

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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
