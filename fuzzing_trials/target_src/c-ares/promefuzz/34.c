// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_init at ares_init.c:67:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_set_servers_csv at ares_update_servers.c:1305:5 in ares.h
// ares_set_servers_ports_csv at ares_update_servers.c:1310:5 in ares.h
// ares_dup at ares_init.c:455:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_set_servers_csv at ares_update_servers.c:1305:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize ares channel
    ares_channel_t *channel = NULL;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) return 0;

    // Prepare servers CSV input
    char *servers_csv = strndup((const char *)Data, Size);
    if (!servers_csv) {
        ares_destroy(channel);
        return 0;
    }

    // Fuzz ares_set_servers_csv multiple times
    for (int i = 0; i < 10; i++) {
        ares_set_servers_csv(channel, servers_csv);
    }

    // Fuzz ares_set_servers_ports_csv
    ares_set_servers_ports_csv(channel, servers_csv);

    // Duplicate the channel
    ares_channel_t *dup_channel = NULL;
    ares_dup(&dup_channel, channel);

    // Destroy the original channel
    ares_destroy(channel);

    // Fuzz ares_set_servers_csv after destruction
    for (int i = 0; i < 3; i++) {
        ares_set_servers_csv(dup_channel, servers_csv);
    }

    // Cleanup
    ares_destroy(dup_channel);
    free(servers_csv);

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
