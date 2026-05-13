#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Initialize pcap_t structure
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535); // Dummy values for linktype and snaplen

    if (handle == NULL) {
        return 0;
    }

    // Ensure the size is sufficient to extract an int value
    if (size < sizeof(int)) {
        pcap_close(handle);
        return 0;
    }

    // Use the first bytes of data as the integer value for the rfmon parameter
    int rfmon = *((int *)data);

    // Call the function-under-test
    pcap_set_rfmon(handle, rfmon);

    // Clean up
    pcap_close(handle);

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

    LLVMFuzzerTestOneInput_96(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
