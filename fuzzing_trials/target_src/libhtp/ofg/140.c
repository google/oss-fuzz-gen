#include <stdint.h>
#include <stdlib.h>
#include <htp/htp.h>
#include <htp/htp_connection_parser.h> // Include this to ensure htp_time_t is defined

int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    // Initialize the htp_connp_t structure
    htp_connp_t *connp = htp_connp_create(NULL);
    if (connp == NULL) {
        return 0;
    }

    // Create a timestamp, assuming htp_time_t is a struct or type that can be zero-initialized
    htp_time_t timestamp = {0};

    // Use the data to simulate some input to the connection parser
    htp_connp_req_data(connp, &timestamp, data, size);

    // Call the function-under-test
    size_t consumed = htp_connp_req_data_consumed(connp);

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

    LLVMFuzzerTestOneInput_140(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
