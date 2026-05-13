#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_122(const unsigned char *data, size_t size) {
    /* Ensure data is not empty and size is within a reasonable range */
    if (size == 0 || size > 512) {
        return 0;
    }

    /* Allocate memory for hostent structure */
    struct hostent *host = (struct hostent *)malloc(sizeof(struct hostent));
    if (!host) {
        return 0;
    }
    memset(host, 0, sizeof(struct hostent));

    /* Call the function-under-test */
    ares_parse_ns_reply(data, (int)size, &host);

    /* Free the allocated hostent structure */
    if (host) {
        ares_free_hostent(host);
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

    LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
