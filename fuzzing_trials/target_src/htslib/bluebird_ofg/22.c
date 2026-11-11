#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h"  // Ensure HTSlib is installed and properly linked

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Initialize variables
    sam_hdr_t *hdr = sam_hdr_init();
    const char *type = "SQ"; // Example type, could vary based on the fuzzing needs
    int pos = 0; // Example position, can be varied

    // Ensure hdr is not NULL
    if (hdr == NULL) {
        return 0;
    }

    // Fuzzing: Try to add some header lines before attempting removal
    if (size > 0) {
        // Create a temporary buffer to hold a line
        char *line = (char *)malloc(size + 1);
        if (line == NULL) {
            sam_hdr_destroy(hdr);
            return 0;
        }

        // Copy data to line buffer and null-terminate
        memcpy(line, data, size);
        line[size] = '\0';

        // Add a line to the header using the fuzzing data
        if (sam_hdr_add_line(hdr, "SQ", "SN", line, "LN", "1000", NULL) < 0) {
            // If adding the line fails, clean up and return
            free(line);
            sam_hdr_destroy(hdr);
            return 0;
        }

        // Free the temporary line buffer
        free(line);
    }

    // Attempt to remove the line at the specified position
    if (sam_hdr_remove_line_pos(hdr, type, pos) < 0) {
        // If removing the line fails, clean up and return
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Clean up
    sam_hdr_destroy(hdr);

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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
