#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "zlib.h"
#include <stdio.h>
#include <unistd.h>  // Include this for the `write`, `close`, and `lseek` functions

int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    // Create a temporary file to be used by gzFile
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

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Open the file with gzopen
    gzFile file = gzdopen(fd, "rb");
    if (file == NULL) {
        close(fd);
        return 0;
    }

    // Read from the gzFile to ensure data is being processed
    char buffer[1024];
    while (gzread(file, buffer, sizeof(buffer)) > 0) {
        // Process the data (in this case, we're just reading it)
    }

    // Clean up
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gzclose with gzclose_w
    gzclose_w(file);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    // The file descriptor is closed by gzclose

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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
