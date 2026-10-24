#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Assuming the function hts_readlines is defined in some library
extern char **hts_readlines(const char *filename, int *n);

int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit
    }

    // Write the fuzz data to the temporary file
    write(fd, data, size);
    close(fd);

    int n = 0;
    // Call the function-under-test with the temporary file
    char **lines = hts_readlines(tmpl, &n);

    // Cleanup: Free the lines if they were allocated
    if (lines != NULL) {
        for (int i = 0; i < n; i++) {
            free(lines[i]);
        }
        free(lines);
    }

    // Remove the temporary file
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_96(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
