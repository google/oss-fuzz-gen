#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Create a temporary file to write the input data
    char tmp_filename[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        return 0; // If we can't create a temp file, return early
    }

    // Write the data to the temporary file
    FILE *tmp_file = fdopen(fd, "wb");
    if (!tmp_file) {
        close(fd);
        return 0;
    }

    fwrite(data, 1, size, tmp_file);
    fclose(tmp_file);

    // Open the file using gf_isom_open
    GF_ISOFile *movie = gf_isom_open(tmp_filename, GF_ISOM_OPEN_READ, NULL);

    if (movie) {
        // Call the function under test
        gf_isom_close(movie);
    }

    // Clean up the temporary file
    remove(tmp_filename);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
