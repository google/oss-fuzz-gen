#include <cstdint> // Include for uint8_t
#include <cstddef> // Include for size_t
#include <cstring> // Include for memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to create a meaningful string
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *input = new char[size + 1];
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    icalcomponent *valarm = icalcomponent_new_valarm();

    // Perform operations on the created component if needed
    if (valarm != NULL) {
        // Example: Add some properties to the valarm component
        icalcomponent_add_property(valarm, icalproperty_new_action(ICAL_ACTION_DISPLAY));
        icalcomponent_add_property(valarm, icalproperty_new_description(input));

        // Correctly create a trigger property using icaltriggertype
        struct icaltriggertype trigger;
        trigger.time = icaltime_from_string("20231010T123000Z");
        icalcomponent_add_property(valarm, icalproperty_new_trigger(trigger));

        // Add additional operations to increase code coverage
        icalcomponent_add_property(valarm, icalproperty_new_summary("Test Summary"));

        // Optionally, convert the component to a string and back to test serialization/deserialization
        char *component_string = icalcomponent_as_ical_string(valarm);
        if (component_string != NULL) {
            icalcomponent *parsed_component = icalparser_parse_string(component_string);
            if (parsed_component != NULL) {
                icalcomponent_free(parsed_component);
            }
            icalmemory_free_buffer(component_string);
        }

        // Clean up by freeing the component
        icalcomponent_free(valarm);
    }

    // Free the allocated input string
    delete[] input;

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

    LLVMFuzzerTestOneInput_107(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
