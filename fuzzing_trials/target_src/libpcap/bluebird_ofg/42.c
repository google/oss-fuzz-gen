#include <sys/stat.h>
#include "pcap/pcap.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    pcap_t *pcap_handle;
    int *datalinks;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ensure the data is null-terminated to prevent buffer overflow
    char *temp_data = (char *)malloc(size + 1);
    if (temp_data == NULL) {
        return 0;
    }
    memcpy(temp_data, data, size);
    temp_data[size] = '\0';

    // Create a pcap_t structure from the provided data
    pcap_handle = pcap_open_offline_with_tstamp_precision(temp_data, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    free(temp_data);
    if (pcap_handle == NULL) {
        return 0;
    }

    // Call the function-under-test
    int result = pcap_list_datalinks(pcap_handle, &datalinks);

    // Free allocated resources
    if (result >= 0) {
        pcap_free_datalinks(datalinks);
    }
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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
