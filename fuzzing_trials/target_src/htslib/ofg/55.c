#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>  // Include for mkstemp, close, and unlink
#include <fcntl.h>   // Include for write
#include <htslib/sam.h>
#include <htslib/hts.h>
#include <htslib/bgzf.h>

// Remove 'extern "C"' for C code compatibility
int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Open the temporary file with BGZF
    BGZF *bgzf = bgzf_open(tmpl, "r");
    if (bgzf == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    sam_hdr_t *header = bam_hdr_read(bgzf);

    // Clean up
    if (header != NULL) {
        sam_hdr_destroy(header);
    }
    bgzf_close(bgzf);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_55(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
