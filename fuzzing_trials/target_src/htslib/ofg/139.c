#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <htslib/sam.h>
#include <htslib/bgzf.h>

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Initialize BGZF file pointer
    BGZF *bgzf = bgzf_open("/dev/null", "w");
    if (bgzf == NULL) {
        return 0;
    }

    // Create a sam_hdr_t object
    sam_hdr_t *hdr = sam_hdr_init();
    if (hdr == NULL) {
        bgzf_close(bgzf);
        return 0;
    }

    // Add some dummy header text to the sam_hdr_t object
    if (sam_hdr_add_line(hdr, "HD", "VN", "1.0", NULL) != 0) {
        sam_hdr_destroy(hdr);
        bgzf_close(bgzf);
        return 0;
    }

    // Use the input data to simulate a realistic scenario
    if (size > 0) {
        // Write the input data to the BGZF file
        if (bgzf_write(bgzf, data, size) < 0) {
            sam_hdr_destroy(hdr);
            bgzf_close(bgzf);
            return 0;
        }
    }

    // Call the function-under-test
    bam_hdr_write(bgzf, hdr);

    // Clean up
    sam_hdr_destroy(hdr);
    bgzf_close(bgzf);

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

    LLVMFuzzerTestOneInput_139(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
