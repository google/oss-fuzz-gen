#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>  // Include for AF_INET
#include "ares.h"

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    /* Allocate a hostent structure */
    struct hostent *host = (struct hostent *)malloc(sizeof(struct hostent));
    if (!host) {
        return 0;
    }

    /* Initialize the hostent structure with some dummy values */
    host->h_name = (char *)malloc(size + 1);
    if (!host->h_name) {
        free(host);
        return 0;
    }
    memcpy(host->h_name, data, size);
    host->h_name[size] = '\0';

    host->h_aliases = (char **)malloc(2 * sizeof(char *));
    if (!host->h_aliases) {
        free(host->h_name);
        free(host);
        return 0;
    }
    host->h_aliases[0] = strdup("alias");
    host->h_aliases[1] = NULL;

    host->h_addrtype = AF_INET;
    host->h_length = 4;

    host->h_addr_list = (char **)malloc(2 * sizeof(char *));
    if (!host->h_addr_list) {
        free(host->h_aliases[0]);
        free(host->h_aliases);
        free(host->h_name);
        free(host);
        return 0;
    }
    host->h_addr_list[0] = (char *)malloc(host->h_length);
    if (!host->h_addr_list[0]) {
        free(host->h_addr_list);
        free(host->h_aliases[0]);
        free(host->h_aliases);
        free(host->h_name);
        free(host);
        return 0;
    }
    memset(host->h_addr_list[0], 0, host->h_length);
    host->h_addr_list[1] = NULL;

    /* Call the function under test */
    ares_free_hostent(host);

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

    LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
