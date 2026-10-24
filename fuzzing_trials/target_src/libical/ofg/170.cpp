#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_170(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent with some basic data
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (component == NULL) {
        return 0;
    }

    // Add a VEVENT component to the VCALENDAR
    icalcomponent *vevent = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (vevent == NULL) {
        icalcomponent_free(component);
        return 0;
    }
    icalcomponent_add_component(component, vevent);

    // Add a VTODO component to the VCALENDAR
    icalcomponent *vtodo = icalcomponent_new(ICAL_VTODO_COMPONENT);
    if (vtodo == NULL) {
        icalcomponent_free(component);
        return 0;
    }
    icalcomponent_add_component(component, vtodo);

    // Use the data to decide which component kind to search for
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(data[0] % ICAL_NO_COMPONENT);

    // Call the function-under-test
    icalcomponent *next_component = icalcomponent_get_next_component(component, kind);

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

    LLVMFuzzerTestOneInput_170(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
