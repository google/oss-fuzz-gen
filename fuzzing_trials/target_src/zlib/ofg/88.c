#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <unistd.h>  // For close() and unlink()

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    // Create a temporary file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the temporary file as a gzFile
    gzFile gz_file = gzopen(tmpl, "rb");
    if (gz_file == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Allocate a buffer to read the data
    unsigned int buffer_size = 1024; // Arbitrary buffer size
    void *buffer = malloc(buffer_size);
    if (buffer == NULL) {
        gzclose(gz_file);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    gzread(gz_file, buffer, buffer_size);

    // Clean up
    free(buffer);
    gzclose(gz_file);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
