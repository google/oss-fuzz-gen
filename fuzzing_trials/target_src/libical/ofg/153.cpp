#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    // Initialize the iCalendar library
    icalcomponent *parent_component;
    icalcomponent *child_component;

    // Create a dummy parent component
    parent_component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (parent_component == NULL) {
        return 0;
    }

    // Create a dummy child component
    child_component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (child_component == NULL) {
        icalcomponent_free(parent_component);
        return 0;
    }

    // Add the child component to the parent component
    icalcomponent_add_component(parent_component, child_component);

    // Fuzz the function by removing the child component from the parent
    icalcomponent_remove_component(parent_component, child_component);

    // Free the parent component
    icalcomponent_free(parent_component);

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

    LLVMFuzzerTestOneInput_153(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
