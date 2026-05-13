#include <stdint.h>
#include <stddef.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the pcap_pkthdr structure
    if (size < sizeof(struct pcap_pkthdr)) {
        return 0;
    }

    // Allocate memory for the pcap_pkthdr structure and packet data
    struct pcap_pkthdr pkthdr;
    u_char *user = (u_char *)malloc(1);  // Dummy user data
    if (user == NULL) {
        return 0; // Handle memory allocation failure
    }
    const u_char *packet_data = data + sizeof(struct pcap_pkthdr);

    // Copy data into the pcap_pkthdr structure
    memcpy(&pkthdr, data, sizeof(struct pcap_pkthdr));

    // Call the function-under-test
    pcap_dump(user, &pkthdr, packet_data);

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

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
