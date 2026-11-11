#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Create a temporary file to write the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }

    // Write the data to the file
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the SAM file using htslib
    samFile *sam_file = sam_open(tmpl, "r");
    if (sam_file) {
        // Call the function-under-test
        sam_hdr_t *header = sam_hdr_get(sam_file);

        // Clean up
        if (header) {
            sam_hdr_destroy(header);
        }
        sam_close(sam_file);
    }

    // Remove the temporary file
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_69(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
