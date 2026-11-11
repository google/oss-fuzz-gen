#include <string.h>
#include <sys/stat.h>
#include <cstdint>  // For uint8_t
#include <cstddef>  // For size_t
#include <cstring>  // For memcpy

extern "C" {
    #include "libical/ical.h"
}

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Initialize the icalcomponent object
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Ensure that the data size is reasonable for the buffer
    if (size > 0 && size < 1024) {
        // Create a temporary buffer to hold the input data
        char buffer[1024];
        memcpy(buffer, data, size);
        buffer[size] = '\0'; // Null-terminate the buffer

        // Parse the buffer into an icalcomponent
        icalcomponent *parsed_component = icalparser_parse_string(buffer);
        if (parsed_component != NULL) {
            // Use the function-under-test
            const char *component_name = icalcomponent_get_component_name(parsed_component);

            // Clean up the parsed component
            // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function icalcomponent_free with icalcomponent_normalize
            icalcomponent_normalize(parsed_component);
            // End mutation: Producer.REPLACE_FUNC_MUTATOR
        }
    }

    // Clean up the initial icalcomponent
    icalcomponent_free(component);

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
