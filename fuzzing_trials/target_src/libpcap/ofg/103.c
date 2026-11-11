#include <stdint.h>
#include <pcap.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(u_int)) {
        return 0;
    }

    // Extract the parameters from the input data
    int linktype = *((int *)data);
    int snaplen = *((int *)(data + sizeof(int)));
    u_int precision = *((u_int *)(data + sizeof(int) * 2));

    // Call the function-under-test
    pcap_t *handle = pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision);

    // Clean up if necessary
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

    LLVMFuzzerTestOneInput_103(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
