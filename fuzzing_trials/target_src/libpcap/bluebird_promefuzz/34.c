#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pcap/pcap.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file != NULL) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    pcap_if_t *alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;

    // Prepare a dummy file if needed by the API
    write_dummy_file(Data, Size);

    // Attempt to call pcap_findalldevs_ex
    struct pcap_rmtauth auth = {0, NULL, NULL};
    int result = pcap_findalldevs_ex("./dummy_file", &auth, &alldevs, errbuf);

    // Call pcap_findalldevs_ex again to explore behavior
    result = pcap_findalldevs_ex("./dummy_file", NULL, &alldevs, errbuf);

    // Call pcap_findalldevs
    result = pcap_findalldevs(&alldevs, errbuf);

    // Use the first device name for pcap_lookupnet if available
    if (alldevs && alldevs->name) {
        result = pcap_lookupnet(alldevs->name, &net, &mask, errbuf);
    }

    // Cleanup
    if (alldevs) {
        pcap_freealldevs(alldevs);
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
