#include <stdint.h>
#include <stddef.h>
#include <htslib/sam.h>
#include <htslib/hts.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_244(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to create a valid filename
    if (size < 5) {
        return 0;
    }

    // Create a temporary file to simulate htsFile input
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    write(fd, data, size);
    close(fd);

    // Open the temporary file as an htsFile
    htsFile *hts_file = hts_open(tmpl, "r");
    if (!hts_file) {
        unlink(tmpl);
        return 0;
    }

    // Create a dummy sam_hdr_t object
    sam_hdr_t *sam_hdr = sam_hdr_init();
    if (!sam_hdr) {
        hts_close(hts_file);
        unlink(tmpl);
        return 0;
    }

    // Use part of the data as the string input for the function
    char *str_input = (char *)malloc(size + 1);
    if (!str_input) {
        sam_hdr_destroy(sam_hdr);
        hts_close(hts_file);
        unlink(tmpl);
        return 0;
    }
    memcpy(str_input, data, size);
    str_input[size] = '\0';

    // Call the function-under-test
    int result = sam_idx_init(hts_file, sam_hdr, 0, str_input);

    // Clean up
    free(str_input);
    sam_hdr_destroy(sam_hdr);
    hts_close(hts_file);
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

    LLVMFuzzerTestOneInput_244(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
