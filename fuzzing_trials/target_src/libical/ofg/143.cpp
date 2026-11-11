#include <cstdint>  // Include for uint8_t
#include <cstddef>  // Include for size_t

extern "C" {
#include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    // Initialize the icalcomponent with some default data
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (component == NULL) {
        return 0;
    }

    // Add a property to ensure the component is not empty
    icalproperty *property = icalproperty_new_summary("Sample Event");
    icalcomponent_add_property(component, property);

    // Ensure the data size is sufficient to extract a property kind
    if (size < sizeof(icalproperty_kind)) {
        icalcomponent_free(component);
        return 0;
    }

    // Extract a property kind from the input data
    icalproperty_kind kind = static_cast<icalproperty_kind>(data[0] % ICAL_NO_PROPERTY);

    // Call the function-under-test
    icalcomponent_remove_property_by_kind(component, kind);

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

    LLVMFuzzerTestOneInput_143(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
