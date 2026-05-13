#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libhtp/htp/htp.h"  // Correct path for the header file
#include "/src/libhtp/htp/htp_connection_parser.h"  // Include the header for htp_connp_t

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    htp_connp_t *connp = htp_connp_create(NULL);  // Use a function to create the connection parser
    htp_time_t current_time;
    const char *host = "example.com";
    const char *client_ip = "192.168.0.1";
    int client_port = 8080;
    int server_port = 80;

    // Ensure the data is not null and has a minimum size
    if (data == NULL || size < sizeof(htp_time_t)) {
        htp_connp_destroy_all(connp);  // Clean up before returning
        return 0;
    }

    // Copy data into current_time to simulate different time values
    memcpy(&current_time, data, sizeof(htp_time_t));

    // Call the function-under-test
    htp_connp_open(connp, host, client_port, client_ip, server_port, &current_time);

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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
