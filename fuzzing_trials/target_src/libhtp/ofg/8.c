#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy function

#include "/src/libhtp/htp/htp.h" // Correct path for htp.h
#include "/src/libhtp/htp/htp_connection_parser.h" // Include for htp_connp_t definition
#include "/src/libhtp/htp/htp_transaction.h" // Include for htp_time_t definition

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    htp_connp_t *connp;
    htp_time_t time;

    // Ensure that the data size is sufficient to populate the structures
    if (size < sizeof(htp_time_t)) {
        return 0;
    }

    // Allocate memory for htp_connp_t
    connp = htp_connp_create(NULL);
    if (connp == NULL) {
        return 0;
    }

    // Initialize htp_time_t with data from the input
    memcpy(&time, data, sizeof(htp_time_t));

    // Call the function-under-test
    htp_connp_req_close(connp, &time);

    // Clean up
    htp_connp_destroy_all(connp);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
