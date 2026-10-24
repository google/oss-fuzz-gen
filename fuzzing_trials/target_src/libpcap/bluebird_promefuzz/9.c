#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pcap/pcap.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pcap_t *initialize_pcap_handle() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create("any", errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        return NULL;
    }
    return handle;
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 3) {
        return 0;
    }

    pcap_t *handle = initialize_pcap_handle();
    if (!handle) {
        return 0;
    }

    int immediate_mode = Data[0] % 2;
    int timeout = ((int *)Data)[1];
    int activation_status;

    // 1. Set immediate mode
    int result = pcap_set_immediate_mode(handle, immediate_mode);
    const char *status_str = pcap_statustostr(result);
    if (result != 0) {
        fprintf(stderr, "pcap_set_immediate_mode failed: %s\n", status_str);
        pcap_close(handle);
        return 0;
    }

    // 2. Set timeout
    result = pcap_set_timeout(handle, timeout);
    status_str = pcap_statustostr(result);
    if (result != 0) {
        fprintf(stderr, "pcap_set_timeout failed: %s\n", status_str);
        pcap_close(handle);
        return 0;
    }

    // 3. Activate the handle
    activation_status = pcap_activate(handle);
    status_str = pcap_statustostr(activation_status);
    if (activation_status < 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", status_str);
        const char *err_msg = pcap_geterr(handle);
        fprintf(stderr, "Error: %s\n", err_msg);
        pcap_close(handle);
        return 0;
    }

    // Get error if any
    if (activation_status != 0) {
        const char *err_msg = pcap_geterr(handle);
        fprintf(stderr, "Activation status warning: %s\n", err_msg);
    }

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
