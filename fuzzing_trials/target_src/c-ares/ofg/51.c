#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <ares.h>
#include <ares_dns.h> // Include the correct header for ares_dns_section_t

// Function prototype for ares_dns_section_tostr
// Ensure it matches the declaration in the ares_dns_record.h
CARES_EXTERN const char *ares_dns_section_tostr(ares_dns_section_t section);

int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    if (size < sizeof(ares_dns_section_t)) {
        return 0; /* Not enough data to form a valid ares_dns_section_t */
    }

    // Interpret the input data as an ares_dns_section_t
    ares_dns_section_t section;
    memcpy(&section, data, sizeof(ares_dns_section_t)); // Use memcpy to avoid alignment issues

    // Call the function-under-test
    const char *result = ares_dns_section_tostr(section);

    // No need to free result as it is a const char *

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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
