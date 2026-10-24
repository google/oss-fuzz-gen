#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>
#include <stdio.h>
#include <unistd.h> // For mkstemp and close
#include <fcntl.h>  // For write

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    gzFile file;
    int level;
    int strategy;
    char filename[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(filename);

    if (fd < 0) {
        return 0;
    }

    // Write data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the file with gzopen
    file = gzopen(filename, "rb");
    if (file == NULL) {
        return 0;
    }

    // Initialize level and strategy with non-zero values
    level = (size > 0) ? (data[0] % 10) : 1;  // Compression level between 0-9
    strategy = (size > 1) ? (data[1] % 4) : 0; // Strategy between 0-3

    // Call the function-under-test
    gzsetparams(file, level, strategy);

    // Close the gzFile
    gzclose(file);

    // Remove the temporary file
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
