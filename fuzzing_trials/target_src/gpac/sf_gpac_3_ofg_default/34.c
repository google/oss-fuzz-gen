#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <gpac/isomedia.h>

// Include the necessary GPAC headers
#include <gpac/constants.h>
#include <gpac/internal/isomedia_dev.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    FILE *tempFile = NULL;
    char tempFileName[] = "/tmp/fuzz_temp_file.XXXXXX";

    // Create a temporary file and write the input data to it
    int fd = mkstemp(tempFileName);
    if (fd == -1) {
        return 0;
    }

    tempFile = fdopen(fd, "wb");
    if (tempFile == NULL) {
        close(fd);
        return 0;
    }

    if (fwrite(data, 1, size, tempFile) != size) {
        fclose(tempFile);
        return 0;
    }

    fclose(tempFile);

    // Open the temporary file as an ISO media file
    movie = gf_isom_open(tempFileName, GF_ISOM_OPEN_READ, NULL);
    if (movie == NULL) {
        // If the movie could not be opened, clean up and return early
        remove(tempFileName);
        return 0;
    }

    // Call the function-under-test
    gf_isom_close(movie);

    // Clean up the temporary file
    remove(tempFileName);

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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
