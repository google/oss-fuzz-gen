#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Call the function-under-test
    sam_hdr_t *hdr = sam_hdr_init();

    // Check if the header was initialized successfully
    if (hdr != NULL) {
        // Attempt to parse the input data as a SAM header
        if (size > 0) {
            // Create a null-terminated string from the input data
            char *input_data = (char *)malloc(size + 1);
            if (input_data != NULL) {
                memcpy(input_data, data, size);
                input_data[size] = '\0';

                // Parse the input data as a SAM header
                sam_hdr_t *parsed_hdr = sam_hdr_parse(size, input_data);

                // Check if parsing was successful
                if (parsed_hdr != NULL) {
                    // Do something with parsed_hdr if needed

                    // Free the parsed header to prevent memory leaks
                    sam_hdr_destroy(parsed_hdr);
                }

                // Free the allocated input data
                free(input_data);
            }
        }

        // Free the allocated header to prevent memory leaks
        sam_hdr_destroy(hdr);
    }

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

    LLVMFuzzerTestOneInput_66(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
