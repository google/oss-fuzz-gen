#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    write(fd, data, size);
    close(fd);

    // Open the temporary file with gzopen
    gzFile gzfile = gzopen(tmpl, "rb");
    if (gzfile == NULL) {
        remove(tmpl);
        return 0;
    }

    // Allocate a buffer to read data into
    unsigned int buffer_size = 1024;
    void *buffer = malloc(buffer_size);
    if (buffer == NULL) {
        gzclose(gzfile);
        remove(tmpl);
        return 0;
    }

    // Call gzread with the buffer
    gzread(gzfile, buffer, buffer_size);

    // Clean up
    free(buffer);
    gzclose(gzfile);
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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
