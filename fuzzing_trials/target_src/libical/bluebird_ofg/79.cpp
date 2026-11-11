#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "libical/ical.h"
}

extern "C" int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    // Initialize variables
    icalcomponent *component = nullptr;
    icalproperty_kind kind = ICAL_NO_PROPERTY;

    // Ensure that size is sufficient to extract at least one character for kind
    if (size > 0) {
        // Create a new icalcomponent
        component = icalcomponent_new(ICAL_VEVENT_COMPONENT);

        // Use the first byte of data to determine the icalproperty_kind
        kind = static_cast<icalproperty_kind>(data[0] % (ICAL_ANY_PROPERTY + 1)); // Fix division by zero

        // Create a new icalproperty with the determined kind
        icalproperty *property = icalproperty_new(kind);

        // Check if property creation was successful
        if (property != nullptr) {
            // Add the property to the component
            icalcomponent_add_property(component, property);

            // Iterate over properties to ensure full coverage
            for (icalproperty *prop = icalcomponent_get_first_property(component, kind);
                 prop != nullptr;
                 prop = icalcomponent_get_next_property(component, kind)) {
                // Process the property in some way
                const char *prop_name = icalproperty_get_property_name(prop);
                if (prop_name) {
                    // Do something with the property name
                }
            }
        }

        // Clean up
        icalcomponent_free(component);
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

    LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
