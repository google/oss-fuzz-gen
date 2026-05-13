#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include for mkstemp and close
#include <fcntl.h>   // Include for open flags

// Assuming the function is declared in a header file
extern char **hts_readlist(const char *filename, int is_file, int *n);

int LLVMFuzzerTestOneInput_263(const uint8_t *data, size_t size) {
    // Define and initialize variables
    char *filename;
    int is_file = 1;  // Assuming we are passing a file
    int n = 0;
    char **result;

    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    
    // Write the fuzz data to the file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }
    close(fd);

    filename = tmpl;

    // Call the function-under-test
    result = hts_readlist(filename, is_file, &n);

    // Clean up
    if (result != NULL) {
        for (int i = 0; i < n; i++) {
            free(result[i]);
        }
        free(result);
    }

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_263(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
