#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    /* Ensure the data is large enough to extract necessary parameters */
    if (size < 10) {
        return 0;
    }

    /* Extract parameters from the input data */
    const char *name = (const char *)data;
    int dnsclass = data[0] % 256; // Example: use first byte for dnsclass
    int type = data[1] % 256;     // Example: use second byte for type
    unsigned short id = (data[2] << 8) | data[3]; // Combine two bytes for id
    int rd = data[4] % 2;         // Example: use fifth byte for rd
    int max_udp_size = (data[5] << 8) | data[6]; // Combine two bytes for max_udp_size

    /* Allocate memory for bufp and buflenp */
    unsigned char *bufp = NULL;
    int buflenp = 0;

    /* Call the function-under-test */
    ares_create_query(name, dnsclass, type, id, rd, &bufp, &buflenp, max_udp_size);

    /* Free allocated memory */
    if (bufp) {
        free(bufp);
    }

    return 0;
}