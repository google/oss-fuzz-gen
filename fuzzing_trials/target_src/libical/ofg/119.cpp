#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to create the necessary objects.
    if (size < 2) {
        return 0;
    }

    // Create a memory context for the ical component and property.
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalproperty *property = icalproperty_new(ICAL_DTSTART_PROPERTY);

    // Set some values to the component and property to ensure they are not NULL.
    icalcomponent_set_method(component, ICAL_METHOD_REQUEST);
    icalproperty_set_dtstart(property, icaltime_from_string("20230101T120000Z"));

    // Call the function-under-test.
    icaltimetype result = icalproperty_get_datetime_with_component(property, component);

    // Clean up by freeing the allocated icalcomponent and icalproperty.
    icalproperty_free(property);
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

    LLVMFuzzerTestOneInput_119(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
