#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    FILE *temp_file = NULL;

    // Create a temporary file to write the buffer data
    temp_file = tmpfile();
    if (temp_file == NULL) {
        return 0;
    }

    // Write the data to the temporary file
    if (fwrite(data, 1, size, temp_file) != size) {
        fclose(temp_file);
        return 0;
    }

    // Rewind the file to the beginning
    rewind(temp_file);

    // Open the ISO media file from the temporary file
    movie = gf_isom_open(temp_file, GF_ISOM_OPEN_READ, NULL);

    // Ensure the movie is not NULL
    if (movie == NULL) {
        fclose(temp_file);
        return 0;
    }

    // Call the function-under-test
    gf_isom_close(movie);

    // Close the temporary file
    fclose(temp_file);

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
