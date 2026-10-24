#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for creating a valid icalcomponent
    if (size < 1) {
        return 0;
    }

    // Create an icalcomponent from the input data
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);

    // Use the first byte of data to determine the kind of component
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(data[0] % (ICAL_NO_COMPONENT + 1));

    // Create a temporary buffer to hold the input data as a string
    char *temp_data = new char[size + 1];
    memcpy(temp_data, data, size);
    temp_data[size] = '\0'; // Null-terminate the string

    // Set the component's properties using the input data
    icalcomponent_set_summary(component, temp_data);

    // Attempt to parse the input data as an iCalendar string
    icalcomponent *parsed_component = icalparser_parse_string(temp_data);
    if (parsed_component) {
        // Iterate over sub-components if parsing was successful
        icalcomponent *sub_component = icalcomponent_get_first_component(parsed_component, kind);
        while (sub_component != NULL) {
            sub_component = icalcomponent_get_next_component(parsed_component, kind);
        }
        icalcomponent_free(parsed_component);
    }

    // Clean up
    delete[] temp_data;
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

    LLVMFuzzerTestOneInput_117(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
