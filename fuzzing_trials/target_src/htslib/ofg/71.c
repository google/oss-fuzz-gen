#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Function-under-test declaration
int sam_index_build3(const char *fn, const char *fnidx, int min_shift, int n_threads);

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to create meaningful inputs
    if (size < 4) {
        return 0;
    }

    // Create temporary files for the input filenames
    char tmpl1[] = "/tmp/fuzzfileXXXXXX";
    char tmpl2[] = "/tmp/fuzzfileXXXXXX";
    int fd1 = mkstemp(tmpl1);
    int fd2 = mkstemp(tmpl2);

    // Write the fuzz data to the first temporary file
    if (fd1 != -1) {
        write(fd1, data, size);
        close(fd1);
    }

    // Write the fuzz data to the second temporary file
    if (fd2 != -1) {
        write(fd2, data, size);
        close(fd2);
    }

    // Extract integer values from the data for the function parameters
    int min_shift = (int)data[0];
    int n_threads = (int)data[1];

    // Call the function-under-test
    sam_index_build3(tmpl1, tmpl2, min_shift, n_threads);

    // Clean up temporary files
    unlink(tmpl1);
    unlink(tmpl2);

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

    LLVMFuzzerTestOneInput_71(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
