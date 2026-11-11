#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include this for mkstemp and unlink
#include <fcntl.h>   // Include this for open and close
#include "htslib/hts.h"
#include "htslib/sam.h"

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    htsFile *hts_file = NULL;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = -1;
    char *fname = NULL;
    char *fnidx = NULL;
    hts_idx_t *idx = NULL;
    int flags = 0;

    // Create a temporary file for the data
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    write(fd, data, size);
    close(fd);

    // Open the temporary file with htslib
    hts_file = hts_open(tmpl, "r");
    if (hts_file == NULL) {
        goto cleanup;
    }

    // Assign non-NULL values to fname and fnidx
    fname = strdup(tmpl);
    fnidx = strdup(tmpl);
    if (fname == NULL || fnidx == NULL) {
        goto cleanup;
    }

    // Call the function-under-test
    idx = sam_index_load3(hts_file, fname, fnidx, flags);

cleanup:
    if (hts_file != NULL) {
        hts_close(hts_file);
    }
    if (fname != NULL) {
        free(fname);
    }
    if (fnidx != NULL) {
        free(fnidx);
    }
    if (idx != NULL) {
        hts_idx_destroy(idx);
    }
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

    LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
