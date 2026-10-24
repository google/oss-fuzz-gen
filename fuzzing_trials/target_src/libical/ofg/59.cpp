#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to contain a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Create a new icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (component == NULL) {
        return 0;
    }

    // Allocate memory for the location string and ensure it is null-terminated
    char *location = (char *)malloc(size + 1);
    if (location == NULL) {
        icalcomponent_free(component);
        return 0;
    }
    memcpy(location, data, size);
    location[size] = '\0';

    // Ensure the location is not an empty string to increase code coverage
    if (strlen(location) == 0) {
        free(location);
        icalcomponent_free(component);
        return 0;
    }

    // Call the function-under-test
    icalcomponent_set_location(component, location);

    // Additional operations to ensure code coverage
    // Attempt to retrieve the location to ensure the function is being tested
    const char *retrieved_location = icalcomponent_get_location(component);
    if (retrieved_location != NULL) {
        // Perform some operation with retrieved_location
        size_t retrieved_length = strlen(retrieved_location);
        if (retrieved_length > 0) {
            // This block ensures that the retrieved location is not null
        }
    }

    // Clean up
    free(location);
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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
