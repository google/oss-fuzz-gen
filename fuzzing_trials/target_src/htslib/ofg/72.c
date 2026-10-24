#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <htslib/sam.h>
#include <htslib/bgzf.h>

// Fuzzing harness for bam_read1 function
int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    // Create a temporary file to store the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the temporary file with BGZF
    BGZF *bgzf = bgzf_open(tmpl, "r");
    if (bgzf == NULL) {
        return 0;
    }

    // Initialize bam1_t structure
    bam1_t *b = bam_init1();
    if (b == NULL) {
        bgzf_close(bgzf);
        return 0;
    }

    // Call the function-under-test
    bam_read1(bgzf, b);

    // Clean up
    bam_destroy1(b);
    bgzf_close(bgzf);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_72(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
