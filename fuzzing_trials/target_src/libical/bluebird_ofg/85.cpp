#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include <cstring> // Include this header for memcpy

extern "C" {
    #include "libical/ical.h"
}

extern "C" int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a valid string
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *icalData = (char *)malloc(size + 1);
    if (icalData == nullptr) {
        return 0;
    }
    memcpy(icalData, data, size);
    icalData[size] = '\0';

    // Parse the iCalendar data into an icalcomponent
    icalcomponent *component = icalparser_parse_string(icalData);

    if (component != nullptr) {
        // Call the function-under-test
        struct icaltimetype dtend = icalcomponent_get_dtend(component);

        // Clean up the component
        icalcomponent_free(component);
    }

    // Free the allocated memory
    free(icalData);

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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
