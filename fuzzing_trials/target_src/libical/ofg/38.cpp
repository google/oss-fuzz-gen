#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // For malloc and free
#include <string.h>  // For memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Initialize the iCalendar component
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Ensure the component is not NULL
    if (component == NULL) {
        return 0;
    }

    // Use the input data to create a string and add it as a summary property
    if (size > 0) {
        // Create a null-terminated string from the input data
        char *summary = (char *)malloc(size + 1);
        if (summary != NULL) {
            memcpy(summary, data, size);
            summary[size] = '\0';  // Null-terminate the string

            // Set a property to the component to ensure it's not empty
            icalproperty *prop = icalproperty_new_summary(summary);
            if (prop != NULL) {
                icalcomponent_add_property(component, prop);
            }

            free(summary);
        }
    }

    // Call the function-under-test
    int sequence = icalcomponent_get_sequence(component);

    // Cleanup
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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
