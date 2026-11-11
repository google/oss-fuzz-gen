#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>        // Include for close() and write()
#include <stdio.h>         // Include for remove()
#include <gpac/isomedia.h> // Include the necessary header for GF_ISOFile and gf_isom_close

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Create a temporary file to simulate an ISO media file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    
    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }
    
    // Close the file descriptor
    close(fd);
    
    // Open the temporary file as a GF_ISOFile
    movie = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);
    if (movie == NULL) {
        remove(tmpl);
        return 0;
    }
    
    // Call the function-under-test
    gf_isom_close(movie);
    
    // Remove the temporary file
    remove(tmpl);
    
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
