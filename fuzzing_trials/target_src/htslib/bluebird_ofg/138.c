#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// Function prototype for the function-under-test
int sam_index_build2(const char *fn, const char *prefix, int min_shift);

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to create meaningful strings
    if (size < 4) { // Increase size check to ensure enough data for meaningful input
        return 0;
    }

    // Create temporary files for the filename and prefix
    char tmpl1[] = "/tmp/fuzzfileXXXXXX";
    char tmpl2[] = "/tmp/fuzzprefixXXXXXX";
    int fd1 = mkstemp(tmpl1);
    int fd2 = mkstemp(tmpl2);

    if (fd1 == -1 || fd2 == -1) {
        if (fd1 != -1) close(fd1);
        if (fd2 != -1) close(fd2);
        return 0;
    }

    // Ensure the temporary files are empty before writing
    ftruncate(fd1, 0);
    ftruncate(fd2, 0);

    // Write data to the temporary files
    size_t half_size = size / 2;
    if (half_size == 0) { // Additional check to avoid zero-length writes
        close(fd1);
        close(fd2);
        unlink(tmpl1);
        unlink(tmpl2);
        return 0;
    }

    if (write(fd1, data, half_size) != half_size) {
        close(fd1);
        close(fd2);
        unlink(tmpl1);
        unlink(tmpl2);
        return 0;
    }

    if (write(fd2, data + half_size, size - half_size) != size - half_size) {
        close(fd1);
        close(fd2);
        unlink(tmpl1);
        unlink(tmpl2);
        return 0;
    }

    // Close the file descriptors
    close(fd1);
    close(fd2);

    // Call the function-under-test with the temporary file paths and a non-zero integer
    // Ensure that the input data is not null and meaningful
    int result = sam_index_build2(tmpl1, tmpl2, 1);
    if (result != 0) {
        // Log error if needed
        fprintf(stderr, "Error: sam_index_build2 returned %d\n", result);
    }

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
