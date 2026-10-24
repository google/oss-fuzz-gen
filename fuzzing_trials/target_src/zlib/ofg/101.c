#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Open the file with gzopen
    gzFile gz = gzdopen(fd, "rb");
    if (gz == NULL) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Read from the gzFile to process the input data
    char buffer[1024];
    while (gzread(gz, buffer, sizeof(buffer)) > 0) {
        // Process the data read from the gzFile
        // This loop will continue until the end of the file is reached
    }

    // Close the gzFile and clean up
    gzclose(gz);
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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
