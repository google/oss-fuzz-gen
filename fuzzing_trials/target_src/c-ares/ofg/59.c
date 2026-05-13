#include <stddef.h>
#include <stdint.h>
#include <string.h>  // Include for memcpy
#include "ares.h"    // Ensure this is the correct header for ares_dns_class_t and ares_dns_class_tostr

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    if (size < sizeof(ares_dns_class_t)) {
        return 0;
    }

    ares_dns_class_t qclass;
    /* Copy data into qclass ensuring it doesn't exceed the size of ares_dns_class_t */
    memcpy(&qclass, data, sizeof(ares_dns_class_t));
    
    /* Call the function-under-test */
    char *result = ares_dns_class_tostr(qclass);
    
    /* Since the function returns a string literal, no need to free the result
       as it is not dynamically allocated. */

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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
