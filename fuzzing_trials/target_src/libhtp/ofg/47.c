#include <stdint.h>
#include <stddef.h>
#include "/src/libhtp/htp/htp.h"

int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Call the function-under-test
    htp_uri_t *uri = htp_uri_alloc();

    // Check if the allocation was successful
    if (uri != NULL) {
        // Parse the input data using htp_parse_uri
        // Correcting the function name from htp_uri_parse to htp_parse_uri
        htp_status_t status = htp_parse_uri(uri, data, size);

        // Optionally, handle the status if needed
        if (status == HTP_OK) {
            // Successfully parsed
        }

        // Free the allocated uri object
        htp_uri_free(uri);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
