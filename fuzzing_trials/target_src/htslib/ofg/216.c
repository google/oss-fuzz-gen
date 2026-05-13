#include <stdint.h>
#include <stdlib.h>
#include <htslib/hts.h>
#include <htslib/sam.h>
#include <string.h>

int LLVMFuzzerTestOneInput_216(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for meaningful operations
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to write the fuzz data
    char filename[] = "/tmp/fuzz_inputXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(filename);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Initialize htsFile to read from the temporary file
    htsFile *file = hts_open(filename, "r");
    if (!file) {
        unlink(filename);
        return 0;
    }

    // Initialize bam1_t for reading alignment records
    bam1_t *b = bam_init1();
    if (!b) {
        hts_close(file);
        unlink(filename);
        return 0;
    }

    // Call the function-under-test
    int result = sam_read1(file, NULL, b);

    // Cleanup
    bam_destroy1(b);
    hts_close(file);
    unlink(filename);

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

    LLVMFuzzerTestOneInput_216(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
