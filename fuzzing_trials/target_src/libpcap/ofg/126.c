#include <pcap.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create two strings
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for the two string parameters
    size_t first_len = size / 2;
    size_t second_len = size - first_len;

    // Allocate memory for the strings and ensure they are null-terminated
    char *device = (char *)malloc(first_len + 1);
    char *errbuf = (char *)malloc(second_len + 1);

    if (device == NULL || errbuf == NULL) {
        free(device);
        free(errbuf);
        return 0;
    }

    memcpy(device, data, first_len);
    device[first_len] = '\0';

    memcpy(errbuf, data + first_len, second_len);
    errbuf[second_len] = '\0';

    // Call the function-under-test
    pcap_t *handle = pcap_create(device, errbuf);

    // Clean up
    free(device);
    free(errbuf);

    // If a handle was created, close it
    if (handle != NULL) {
        pcap_close(handle);
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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
