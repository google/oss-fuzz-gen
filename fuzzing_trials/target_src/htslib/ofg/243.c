#include <stdint.h>
#include <stddef.h>
#include <htslib/sam.h>
#include <htslib/hts.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // Include this for the close() and unlink() functions

int LLVMFuzzerTestOneInput_243(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate an htsFile
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *file = fdopen(fd, "w+");
    if (!file) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fflush(file);
    fseek(file, 0, SEEK_SET);

    // Open the temporary file as an htsFile
    htsFile *hts_file = hts_open(tmpl, "r");
    if (!hts_file) {
        fclose(file);
        return 0;
    }

    // Initialize a sam_hdr_t object
    sam_hdr_t *sam_header = sam_hdr_init();
    if (!sam_header) {
        hts_close(hts_file);
        fclose(file);
        return 0;
    }

    // Set a non-NULL string for the const char* parameter
    const char *c_str = "index";

    // Call the function-under-test
    int result = sam_idx_init(hts_file, sam_header, 0, c_str);

    // Clean up
    sam_hdr_destroy(sam_header);
    hts_close(hts_file);
    fclose(file);
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

    LLVMFuzzerTestOneInput_243(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
