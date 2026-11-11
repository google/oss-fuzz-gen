// This fuzz driver is generated for library libpcap, aiming to fuzz the following functions:
// pcap_lookupnet at pcap.c:1545:1 in pcap.h
// pcap_datalink_name_to_val at pcap.c:3415:1 in pcap.h
// pcap_set_datalink at pcap.c:3066:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_close at pcap.c:4323:1 in pcap.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    int ret;
    pcap_t *handle = NULL;

    if (Size < 1) return 0;

    // Step 1: Use pcap_lookupnet
    ret = pcap_lookupnet("lo", &net, &mask, errbuf);
    if (ret == -1) {
        // Handle error, retrieve error message
        printf("pcap_lookupnet error: %s\n", errbuf);
    }

    // Step 2: Use pcap_datalink_name_to_val
    char dlt_name[16];
    snprintf(dlt_name, sizeof(dlt_name), "EN10MB");
    int dlt_val = pcap_datalink_name_to_val(dlt_name);

    // Step 3: Use pcap_set_datalink
    if (handle) {
        ret = pcap_set_datalink(handle, dlt_val);
        if (ret != 0) {
            // Handle error, retrieve error message
            const char *error = pcap_geterr(handle);
            printf("pcap_set_datalink error: %s\n", error);
        }
    }

    // Step 4: Use pcap_close
    if (handle) {
        pcap_close(handle);
    }

    // Write dummy file with input data
    write_dummy_file(Data, Size);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
