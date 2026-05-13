// This fuzz driver is generated for library libpcap, aiming to fuzz the following functions:
// pcap_create at pcap.c:2304:1 in pcap.h
// pcap_activate at pcap.c:2757:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_close at pcap.c:4323:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_list_datalinks at pcap.c:3016:1 in pcap.h
// pcap_statustostr at pcap.c:3717:1 in pcap.h
// pcap_datalink_val_to_name at pcap.c:3427:1 in pcap.h
// pcap_free_datalinks at pcap.c:3060:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_close at pcap.c:4323:1 in pcap.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static pcap_t *initialize_pcap() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create("dummy_device", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        return NULL;
    }
    if (pcap_activate(handle) != 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    return handle;
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    pcap_t *pcap_handle = initialize_pcap();
    if (pcap_handle == NULL) {
        return 0;
    }

    // pcap_geterr
    char *error_msg = pcap_geterr(pcap_handle);
    if (error_msg != NULL) {
        printf("pcap_geterr: %s\n", error_msg);
    }

    // pcap_list_datalinks
    int *datalinks;
    int datalink_count = pcap_list_datalinks(pcap_handle, &datalinks);
    if (datalink_count == PCAP_ERROR) {
        const char *status_msg = pcap_statustostr(datalink_count);
        printf("pcap_list_datalinks failed: %s\n", status_msg);
    } else {
        for (int i = 0; i < datalink_count; ++i) {
            // pcap_datalink_val_to_name
            const char *dlt_name = pcap_datalink_val_to_name(datalinks[i]);
            if (dlt_name != NULL) {
                printf("DLT %d: %s\n", datalinks[i], dlt_name);
            }
        }
        // pcap_free_datalinks
        pcap_free_datalinks(datalinks);
    }

    // pcap_geterr again
    error_msg = pcap_geterr(pcap_handle);
    if (error_msg != NULL) {
        printf("pcap_geterr: %s\n", error_msg);
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
