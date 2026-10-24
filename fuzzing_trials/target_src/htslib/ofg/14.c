#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include for close() and unlink()
#include <fcntl.h>  // Include for mkstemp()
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    char tmpl1[] = "/tmp/fuzzfileXXXXXX";
    char tmpl2[] = "/tmp/fuzzfileXXXXXX";
    int fd1, fd2;
    hts_idx_t *idx;

    // Create temporary files
    fd1 = mkstemp(tmpl1);
    fd2 = mkstemp(tmpl2);

    if (fd1 == -1 || fd2 == -1) {
        if (fd1 != -1) close(fd1);
        if (fd2 != -1) close(fd2);
        return 0;
    }

    // Write data to the first temporary file
    if (write(fd1, data, size) == -1) {
        close(fd1);
        close(fd2);
        return 0;
    }

    // Close the file descriptors
    close(fd1);
    close(fd2);

    // Call the function-under-test
    idx = hts_idx_load3(tmpl1, tmpl2, HTS_FMT_CSI, 0);

    // Clean up
    if (idx != NULL) {
        hts_idx_destroy(idx);
    }

    // Remove temporary files
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

    LLVMFuzzerTestOneInput_14(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
