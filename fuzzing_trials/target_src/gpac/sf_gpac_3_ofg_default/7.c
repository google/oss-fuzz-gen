#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // To fix the error, we need to adjust the call to gf_isom_open
    // We will use a temporary file approach since gf_isom_open expects a fileName
    char tmp_filename[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        return 0; // If we can't create the file, just return
    }

    // Write the data to the temporary file
    write(fd, data, size);
    close(fd);

    // Open the temporary file using gf_isom_open
    movie = gf_isom_open(tmp_filename, GF_ISOM_OPEN_READ, NULL);

    if (movie != NULL) {
        // Call the function-under-test
        gf_isom_close(movie);
    }

    // Clean up the temporary file
    unlink(tmp_filename);

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
