#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "zlib.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h> // Include unistd.h for close() and mkstemp()

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Define and initialize parameters for gzfwrite
    void *voidpc = (void *)data;
    z_size_t itemsize = size > 0 ? 1 : 0; // Ensure itemsize is non-zero if size is non-zero
    z_size_t nitems = size / itemsize; // Calculate number of items
    gzFile gzfile;

    // Create a temporary file to use with gzopen
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit early
    }

    // Open the temporary file with gzopen
    gzfile = gzdopen(fd, "wb");
    if (gzfile == NULL) {
        close(fd);
        return 0; // If gzopen fails, exit early
    }

    // Call the function-under-test
    gzfwrite(voidpc, itemsize, nitems, gzfile);

    // Clean up
    gzclose(gzfile);
    remove(tmpl); // Remove the temporary file

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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
