#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_156(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated for safe string operations
    char *input_data = (char *)malloc(size + 1);
    if (input_data == NULL) {
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Parse the input data into an icalcomponent
    icalcomponent *child_component = icalparser_parse_string(input_data);
    free(input_data);

    // Initialize a parent icalcomponent
    icalcomponent *parent_component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Ensure the child component is not NULL
    if (child_component == NULL) {
        icalcomponent_free(parent_component);
        return 0;
    }

    // Add the parsed child component to the parent component
    icalcomponent_add_component(parent_component, child_component);

    // Clean up by freeing the components
    icalcomponent_free(parent_component);
    // Note: child_component is already added to parent_component and will be freed with it

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

    LLVMFuzzerTestOneInput_156(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
