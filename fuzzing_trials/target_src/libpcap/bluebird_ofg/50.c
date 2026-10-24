#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "pcap/pcap.h"
#include <string.h>

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Ensure there is enough data to split into meaningful parts
    if (size < 263 + 256) return 0; // Adjust size check to ensure we have enough data

    // Allocate buffers for the parameters
    char source[256] = {0};
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    // Split the input data into parts for the parameters
    // Ensure each part is null-terminated and does not exceed buffer size
    char type_buf[2] = {0};
    char host_buf[256] = {0};
    char port_buf[6] = {0}; // Enough to hold a port number as a string
    char name_buf[256] = {0};

    // Copy data into buffers with proper bounds checking
    type_buf[0] = data[0];
    strncpy(host_buf, (const char *)(data + 1), sizeof(host_buf) - 1);
    strncpy(port_buf, (const char *)(data + 257), sizeof(port_buf) - 1);
    strncpy(name_buf, (const char *)(data + 263), sizeof(name_buf) - 1);

    // Ensure null-termination of strings
    host_buf[sizeof(host_buf) - 1] = '\0';
    port_buf[sizeof(port_buf) - 1] = '\0';
    name_buf[sizeof(name_buf) - 1] = '\0';

    // Call the function-under-test
    if (pcap_createsrcstr(source, sizeof(source), type_buf, host_buf, port_buf, name_buf) != 0) {
        // Handle error if needed, for now just return
        return 0;
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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
