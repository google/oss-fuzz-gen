#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    gzFile file;
    int level;
    int strategy;
    char filename[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(filename);

    if (fd == -1) {
        return 0;
    }

    // Write data to the temporary file
    write(fd, data, size);
    close(fd);

    // Open the file with gzopen
    file = gzopen(filename, "rb");
    if (file == NULL) {
        return 0;
    }

    // Initialize parameters
    level = (size > 0) ? data[0] % 10 : 0; // Compression level between 0 and 9
    strategy = (size > 1) ? data[1] % 4 : 0; // Strategy between 0 and 3

    // Call the function-under-test
    gzsetparams(file, level, strategy);

    // Clean up
    gzclose(file);
    remove(filename);

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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
