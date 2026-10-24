#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    GF_ISOFile *movie = NULL;
    u64 top_box_start = 0;
    
    // Write data to a temporary file
    char tmp_filename[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        return 0;
    }
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }
    close(fd);

    // Open the temporary file as an ISO movie
    movie = gf_isom_open(tmp_filename, GF_ISOM_OPEN_READ, NULL);
    if (movie == NULL) {
        remove(tmp_filename);
        return 0;
    }

    // Call the function-under-test
    gf_isom_reset_data_offset(movie, &top_box_start);

    // Close the movie object using the library's function
    gf_isom_close(movie);

    // Remove the temporary file
    remove(tmp_filename);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
