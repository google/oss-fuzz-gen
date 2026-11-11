#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_169(const uint8_t *data, size_t size) {
    // Initialize the icalcomponent structure
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (component == NULL) {
        return 0;
    }

    // Create a dummy subcomponent to ensure there is at least one component
    icalcomponent *subcomponent = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (subcomponent == NULL) {
        icalcomponent_free(component);
        return 0;
    }

    // Add properties to the subcomponent using the fuzzing data
    if (size > 0) {
        char *summary = (char *)malloc(size + 1);
        if (summary) {
            memcpy(summary, data, size);
            summary[size] = '\0';
            icalproperty *prop = icalproperty_new_summary(summary);
            if (prop) {
                icalcomponent_add_property(subcomponent, prop);
            }
            free(summary);
        }
    }

    // Add additional properties to increase code coverage
    if (size > 1) {
        char *location = (char *)malloc(size + 1);
        if (location) {
            memcpy(location, data, size);
            location[size] = '\0';
            icalproperty *location_prop = icalproperty_new_location(location);
            if (location_prop) {
                icalcomponent_add_property(subcomponent, location_prop);
            }
            free(location);
        }
    }

    icalcomponent_add_component(component, subcomponent);

    // Define the icalcomponent_kind, using a valid kind from the enum
    icalcomponent_kind kind = ICAL_VEVENT_COMPONENT;

    // Call the function-under-test
    icalcomponent *next_component = icalcomponent_get_first_component(component, kind);

    // If the component is found, perform additional operations to ensure coverage
    while (next_component != NULL) {
        // Use more properties to exercise more code paths
        icalproperty *summary_prop = icalcomponent_get_first_property(next_component, ICAL_SUMMARY_PROPERTY);
        if (summary_prop) {
            const char *summary_value = icalproperty_get_summary(summary_prop);
            if (summary_value) {
                // Perform some operation with the summary value
                size_t length = strlen(summary_value);
                if (length > 0) {
                    // Dummy operation to use the summary value
                    (void)length;
                }
            }
        }
        
        // Additional property checks
        icalproperty *location_prop = icalcomponent_get_first_property(next_component, ICAL_LOCATION_PROPERTY);
        if (location_prop) {
            const char *location_value = icalproperty_get_location(location_prop);
            if (location_value) {
                // Perform some operation with the location value
                size_t length = strlen(location_value);
                if (length > 0) {
                    // Dummy operation to use the location value
                    (void)length;
                }
            }
        }

        next_component = icalcomponent_get_next_component(component, kind);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_169(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
