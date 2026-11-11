extern "C" {
#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
}

extern "C" int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent and icalproperty for the iterator
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    icalproperty *property = icalproperty_new_summary("Sample Summary");

    // Add the property to the component
    icalcomponent_add_property(component, property);

    // Initialize the icalproperty iterator
    icalproperty *next_property = nullptr;
    for (next_property = icalcomponent_get_first_property(component, ICAL_ANY_PROPERTY);
         next_property != nullptr;
         next_property = icalcomponent_get_next_property(component, ICAL_ANY_PROPERTY)) {
        // Process each property if needed
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

    LLVMFuzzerTestOneInput_128(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
