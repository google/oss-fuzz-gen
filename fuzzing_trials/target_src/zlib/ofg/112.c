#include <stdint.h>
#include <stddef.h>
#include <zlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
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

    // Close the file descriptor so gzopen can open it
    close(fd);

    // Open the file with gzopen
    gzFile gz_file = gzopen(tmpl, "rb");
    if (gz_file == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Define a non-zero offset and a valid whence value
    off_t offset = (off_t)(size / 2); // Seek to the middle of the data
    int whence = SEEK_SET; // Valid values are SEEK_SET, SEEK_CUR, and SEEK_END

    // Call the function-under-test
    off_t result = gzseek(gz_file, offset, whence);

    // Clean up
    gzclose(gz_file);
    unlink(tmpl);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
