#include <stdint.h>
#include <stdio.h>
#include <zlib.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Ensure there's enough data for the test
    }

    // Create a temporary file to use with gzFile
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Failed to create a temporary file
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0; // Failed to write data to the file
    }

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Open the file with gzopen
    gzFile gz_file = gzdopen(fd, "rb");
    if (gz_file == NULL) {
        close(fd);
        return 0; // Failed to open the file with gzdopen
    }

    // Use the first byte of data as the character to unget
    int unget_char = (int)data[0];

    // Call the function-under-test
    gzungetc(unget_char, gz_file);

    // Clean up
    gzclose(gz_file);
    unlink(tmpl); // Remove the temporary file

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

    LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
