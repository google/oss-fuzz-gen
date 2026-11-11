#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // For close() and unlink()
#include <fcntl.h>   // For mkstemp()
#include "htslib/sam.h"
#include "htslib/hts.h"

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to form a valid header
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to write the header
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Initialize htsFile for writing
    htsFile *hts_fp = hts_open(tmpl, "w");
    if (hts_fp == NULL) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Create a string from the input data
    char *header_str = (char *)malloc(size + 1);
    if (header_str == NULL) {
        hts_close(hts_fp);
        close(fd);
        unlink(tmpl);
        return 0;
    }
    memcpy(header_str, data, size);
    header_str[size] = '\0';

    // Parse the header string into the sam_hdr_t object
    sam_hdr_t *parsed_hdr = sam_hdr_parse(size, header_str);
    free(header_str);  // Free the header string after parsing
    if (parsed_hdr == NULL) {
        hts_close(hts_fp);
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    if (sam_hdr_write(hts_fp, parsed_hdr) < 0) {
        // Handle error if needed
    }

    // Clean up
    sam_hdr_destroy(parsed_hdr);
    hts_close(hts_fp);
    close(fd);
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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
