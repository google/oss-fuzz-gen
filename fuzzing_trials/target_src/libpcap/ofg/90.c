#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    pcap_t *pcap_handle = pcap_open_dead(DLT_RAW, 65535);  // Open a fake pcap handle
    pcap_direction_t direction;

    // Ensure the size is adequate to derive a direction
    if (size > 0) {
        // Use the first byte of data to set the direction
        direction = (pcap_direction_t)(data[0] % 3); // Modulo 3 to get a valid direction
    } else {
        direction = PCAP_D_INOUT; // Default direction if size is 0
    }

    // Call the function-under-test
    int result = pcap_setdirection(pcap_handle, direction);

    // Clean up
    pcap_close(pcap_handle);

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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
