#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Wrap the inclusion of libical headers and usage of its functions with extern "C"
extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_163(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent structure
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Ensure the component is not NULL
    if (component == NULL) {
        return 0;
    }

    // Add some properties to the component to make it non-empty
    icalproperty *prop = icalproperty_new_comment("Sample comment");
    icalcomponent_add_property(component, prop);

    // Call the function-under-test
    const char *component_name = icalcomponent_get_component_name(component);

    // Use the component_name in some way to avoid compiler optimizations
    if (component_name != NULL) {
        // Print the component name (in real fuzzing, this might be logged)
        printf("Component Name: %s\n", component_name);
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

    LLVMFuzzerTestOneInput_163(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
