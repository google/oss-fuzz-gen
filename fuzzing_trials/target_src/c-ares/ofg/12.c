#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <sys/socket.h>  // For AF_INET

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    ares_channel channel;
    struct ares_options options;
    int optmask = 0;
    int status;

    /* Initialize the ares library */
    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    /* Initialize the ares channel */
    status = ares_init_options(&channel, &options, optmask);
    if (status != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    /* Create a dummy ares_addr_node structure */
    struct ares_addr_node servers;
    memset(&servers, 0, sizeof(servers));

    /* Ensure that the size is at least the size of ares_addr_node */
    if (size >= sizeof(servers.addr.addr4)) {
        /* Copy data into the servers structure */
        memcpy(&servers.addr.addr4, data, sizeof(servers.addr.addr4));
        servers.family = AF_INET;  /* Set to IPv4 */
    }

    /* Call the function under test */
    ares_set_servers(&channel, &servers);

    /* Clean up */
    ares_destroy(channel);
    ares_library_cleanup();

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
