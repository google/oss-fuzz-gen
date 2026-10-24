#include <cstdint>  // For uint8_t
#include <cstddef>  // For size_t
#include <cstring>  // For memcpy

extern "C" {
#include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    // Create a new VJOURNAL component
    icalcomponent *vjournal = icalcomponent_new_vjournal();

    // If the data is large enough, attempt to parse it as a string
    if (size > 0) {
        // Create a null-terminated string from the input data
        char *ical_string = (char *)malloc(size + 1);
        if (ical_string == NULL) {
            return 0;
        }
        memcpy(ical_string, data, size);
        ical_string[size] = '\0';

        // Parse the string into an icalcomponent
        icalcomponent *parsed_component = icalparser_parse_string(ical_string);
        if (parsed_component != NULL) {
            // Do something with the parsed component if needed
            icalcomponent_free(parsed_component);
        }

        free(ical_string);
    }

    // Clean up the created component to prevent memory leaks
    if (vjournal != NULL) {
        icalcomponent_free(vjournal);
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

    LLVMFuzzerTestOneInput_115(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
