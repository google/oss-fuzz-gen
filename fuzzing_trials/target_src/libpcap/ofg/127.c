#include <stdint.h>
#include <stddef.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Ensure there is enough data to form two strings
    if (size < 2) {
        return 0;
    }

    // Allocate memory for the device and error buffer strings
    char *device = (char *)malloc(size / 2 + 1);
    char *errbuf = (char *)malloc(size / 2 + 1);

    // Ensure memory allocation was successful
    if (device == NULL || errbuf == NULL) {
        free(device);
        free(errbuf);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(device, data, size / 2);
    device[size / 2] = '\0';

    memcpy(errbuf, data + size / 2, size / 2);
    errbuf[size / 2] = '\0';

    // Call the function-under-test
    pcap_t *handle = pcap_create(device, errbuf);

    // Clean up
    if (handle != NULL) {
        pcap_close(handle);
    }
    free(device);
    free(errbuf);

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

    LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
