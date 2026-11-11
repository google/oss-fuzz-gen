#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include this for mkstemp and unlink
#include "htslib/hts.h"

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for two filenames
    if (size < 4) {
        return 0;
    }

    // Create temporary files for the function inputs
    char tmpl1[] = "/tmp/fuzzfile1XXXXXX";
    char tmpl2[] = "/tmp/fuzzfile2XXXXXX";
    int fd1 = mkstemp(tmpl1);
    int fd2 = mkstemp(tmpl2);

    if (fd1 == -1 || fd2 == -1) {
        return 0;
    }

    // Write data to the first temporary file
    write(fd1, data, size / 2);
    close(fd1);

    // Write data to the second temporary file
    write(fd2, data + size / 2, size - size / 2);
    close(fd2);

    // Call the function-under-test
    hts_idx_t *idx = hts_idx_load2(tmpl1, tmpl2);

    // Clean up
    if (idx != NULL) {
        hts_idx_destroy(idx);
    }
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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
