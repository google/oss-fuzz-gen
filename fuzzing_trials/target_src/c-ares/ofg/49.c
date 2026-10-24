#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <arpa/nameser.h> /* For C_IN and T_A */

// Ensure the function is declared with C linkage
int LLVMFuzzerTestOneInput_49(const unsigned char *data, size_t size) {
    /* Ensure the data size is sufficient for creating a valid name string */
    if (size < 1) {
        return 0;
    }

    /* Create a null-terminated string for the 'name' parameter */
    char *name = (char *)malloc(size + 1);
    if (!name) {
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    /* Initialize other parameters for ares_mkquery */
    int dnsclass = C_IN;  // Internet class
    int type = T_A;       // Type A (IPv4 address)
    unsigned short id = 1; // Arbitrary ID
    int rd = 1;           // Recursion desired
    unsigned char *buf = NULL;
    int buflen = 0;

    /* Call the function-under-test */
    ares_mkquery(name, dnsclass, type, id, rd, &buf, &buflen);

    /* Free allocated resources */
    free(name);
    if (buf) {
        free(buf);
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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
