#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent with some default values
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);

    // Ensure the component is not NULL
    if (component == NULL) {
        return 0;
    }

    // Set a default location to ensure the component is not empty
    icalcomponent_set_location(component, "Default Location");

    // Call the function-under-test
    const char *location = icalcomponent_get_location(component);

    // Use the location to prevent any compiler optimizations from removing the call
    if (location != NULL) {
        // Do something with location, like printing it or logging
        // For fuzzing purposes, we can just ensure it's not NULL
        (void)location; // Suppress unused variable warning
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

    LLVMFuzzerTestOneInput_142(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
