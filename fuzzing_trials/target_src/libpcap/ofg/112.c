#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    u_char *user = (u_char *)malloc(size);
    struct pcap_pkthdr header;
    const u_char *packet_data = data;

    // Ensure user is not NULL
    if (user == NULL) {
        return 0;
    }

    // Initialize header with some values
    header.ts.tv_sec = 0; // Set timestamp seconds
    header.ts.tv_usec = 0; // Set timestamp microseconds
    header.caplen = size; // Set captured length to size
    header.len = size; // Set original length to size

    // Copy data to user to ensure it's not NULL
    for (size_t i = 0; i < size; ++i) {
        user[i] = data[i];
    }

    // Call the function-under-test
    pcap_dump(user, &header, packet_data);

    // Free allocated memory
    free(user);

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

    LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
