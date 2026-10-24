#include <string.h>
#include <sys/stat.h>
#include <cstdint>  // Include for uint8_t
#include <cstddef>  // Include for size_t
#include <cstring>  // Include for memcpy

extern "C" {
    #include "libical/ical.h"
}

extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Create a string buffer from the input data
    char *buffer = (char *)malloc(size + 1);
    if (buffer == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0'; // Null-terminate the string

    // Parse the input data as an iCalendar component
    icalcomponent *component = icalparser_parse_string(buffer);

    // Clean up the created component and buffer to avoid memory leaks
    if (component != NULL) {
        icalcomponent_free(component);
    }
    free(buffer);

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

    LLVMFuzzerTestOneInput_89(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
