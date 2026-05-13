#include <sys/stat.h>
extern "C" {
#include "libical/ical.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 1) {
        return 0;
    }

    // Declare and initialize the necessary variables
    icalproperty *property = nullptr;
    icalcomponent *component = nullptr;
    struct icaltimetype result;

    // Create a new icalproperty and icalcomponent for testing
    property = icalproperty_new(ICAL_DTSTART_PROPERTY);
    component = icalcomponent_new(ICAL_VEVENT_COMPONENT);

    // Ensure both property and component are non-NULL
    if (property != nullptr && component != nullptr) {
        // Use the fuzz input data to set a value in the property
        // Convert the data to a string, assuming it's valid UTF-8
        char *data_str = (char *)malloc(size + 1);
        if (data_str != nullptr) {
            memcpy(data_str, data, size);
            data_str[size] = '\0'; // Null-terminate the string

            // Set the string as a value for the property
            icalproperty_set_value(property, icalvalue_new_string(data_str));

            // Free the temporary string buffer
            free(data_str);
        }

        // Add the property to the component
        icalcomponent_add_property(component, property);

        // Set a valid date-time value to increase the likelihood of non-null results
        struct icaltimetype dtstart = icaltime_from_string("20230101T000000Z");
        if (!icaltime_is_null_time(dtstart)) {
            icalproperty_set_dtstart(property, dtstart);
        }

        // Call the function-under-test
        result = icalproperty_get_datetime_with_component(property, component);

        // Utilize the result to ensure the function is invoked effectively
        if (!icaltime_is_null_time(result)) { // Check if result is not null
            // Convert the result to a string to simulate further processing
            const char *result_str = icaltime_as_ical_string(result);
            if (result_str) {
                // Simulate some processing with the result string
                size_t result_len = strlen(result_str);
                if (result_len > 0) {
                    // Do something with the result string
                }
                // No need to free result_str as icaltime_as_ical_string does not allocate memory
            }
        }
    }

    // Clean up and free the allocated resources
    if (property != nullptr) {
        icalproperty_free(property);
    }
    if (component != nullptr) {
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
