#include <stdint.h>
#include <stddef.h>
#include <zlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

int LLVMFuzzerTestOneInput_160(const uint8_t *data, size_t size) {
    int fd;
    const char *mode = "rb";

    // Create a temporary file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Call the function-under-test
    gzFile gz = gzdopen(fd, mode);

    // Close the gzFile if it was successfully opened
    if (gz != NULL) {
        gzclose(gz);
    } else {
        close(fd);
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

    LLVMFuzzerTestOneInput_160(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
