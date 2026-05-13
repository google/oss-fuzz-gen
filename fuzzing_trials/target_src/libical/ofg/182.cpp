#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_182(const uint8_t *data, size_t size) {
    // Ensure the input is null-terminated
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Parse the input as an iCalendar component
    icalcomponent *component = icalparser_parse_string(input);
    if (component != NULL) {
        // If parsing is successful, iterate over properties
        for (icalproperty *prop = icalcomponent_get_first_property(component, ICAL_ANY_PROPERTY);
             prop != NULL;
             prop = icalcomponent_get_next_property(component, ICAL_ANY_PROPERTY)) {
            // Do something with the property to ensure code coverage
            const char *value = icalproperty_get_value_as_string(prop);
            if (value) {
                // Perform some operation on the value
                icalproperty_set_comment(prop, value);
            }
        }

        // Clean up the component
        icalcomponent_free(component);
    }

    free(input);
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

    LLVMFuzzerTestOneInput_182(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
