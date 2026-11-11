#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <libical/icalcomponent.h>
    #include <libical/icalproperty.h>
}

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Ensure that the data is long enough to create a meaningful summary
    if (size < 5) { // Arbitrary minimum size for meaningful input
        return 0;
    }

    char *summary = (char *)malloc(size + 1);
    if (summary == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(summary, data, size);
    summary[size] = '\0';

    // Create a new icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (component == NULL) {
        free(summary);
        return 0; // Exit if component creation fails
    }

    // Call the function-under-test
    icalcomponent_set_summary(component, summary);

    // Check if the summary was set correctly
    const char *retrieved_summary = icalcomponent_get_summary(component);
    if (retrieved_summary != NULL && strcmp(retrieved_summary, summary) != 0) {
        // Log or handle the error if the summary does not match
    }

    // Set additional properties to increase code coverage
    icalcomponent_set_dtstart(component, icaltime_from_timet_with_zone(time(NULL), 0, NULL));

    // Clean up
    icalcomponent_free(component);
    free(summary);

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
