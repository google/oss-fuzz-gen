#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <htslib/sam.h>
#include <htslib/bgzf.h>

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Create a temporary file to use with BGZF
    char tmpl[] = "/tmp/fuzzbgzfXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Open the temporary file with BGZF
    BGZF *bgzf = bgzf_fdopen(fd, "w");
    if (bgzf == NULL) {
        close(fd);
        return 0;
    }

    // Create a sam_hdr_t object
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        bgzf_close(bgzf);
        return 0;
    }

    // Use the input data to initialize the header
    // Ensure that the input data is null-terminated for safe string operations
    char *header_text = (char *)malloc(size + 1);
    if (header_text == NULL) {
        sam_hdr_destroy(hdr);
        bgzf_close(bgzf);
        return 0;
    }
    memcpy(header_text, data, size);
    header_text[size] = '\0';

    if (sam_hdr_add_lines(hdr, header_text, 0) < 0) {
        free(header_text);
        sam_hdr_destroy(hdr);
        bgzf_close(bgzf);
        return 0;
    }

    // Call the function-under-test
    bam_hdr_write(bgzf, hdr);

    // Clean up
    free(header_text);
    sam_hdr_destroy(hdr);
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

    LLVMFuzzerTestOneInput_138(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
