#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h> // Include for struct hostent
#include <sys/socket.h> // Include for AF_INET
#include "ares.h"

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    /* Initialize ares library */
    ares_library_init(ARES_LIB_INIT_ALL);

    /* Create a channel */
    ares_channel channel;
    if (ares_init(&channel) != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    /* Allocate memory for the hostent structure */
    struct hostent *host = NULL;

    /* Convert the input data to a null-terminated string for the hostname */
    char *name = (char *)malloc(size + 1);
    if (!name) {
        ares_destroy(channel);
        ares_library_cleanup();
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    /* Call the function-under-test */
    int family = AF_INET; /* Use AF_INET as a default family */
    ares_gethostbyname_file(&channel, name, family, &host);

    /* Clean up */
    if (host) {
        ares_free_hostent(host);
    }
    free(name);
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

    LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
