#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <zlib.h>
#include <fcntl.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    // Create a temporary file to work with
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }

    // Reset the file offset to the beginning
    lseek(fd, 0, SEEK_SET);

    // Define a mode string for gzdopen
    const char *mode = "rb";  // Read binary mode

    // Call the function-under-test
    gzFile gz = gzdopen(fd, mode);

    // If gzFile is successfully opened, close it
    if (gz != NULL) {
        gzclose(gz);
    } else {
        close(fd); // Close the file descriptor if gzdopen fails
    }

    // Remove the temporary file
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

    LLVMFuzzerTestOneInput_159(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
