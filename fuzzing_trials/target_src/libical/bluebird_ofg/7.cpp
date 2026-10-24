#include <sys/stat.h>
#include "libical/ical.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Ensure the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Create a summary from the input data
    char summary[size + 1];
    memcpy(summary, data, size);
    summary[size] = '\0'; // Null-terminate the string

    // Initialize a dummy icalcomponent with the input data as the summary
    icalcomponent *component = icalcomponent_vanew(
        ICAL_VEVENT_COMPONENT,
        icalproperty_new_dtstamp(icaltime_from_timet_with_zone(time(NULL), 0, NULL)),
        icalproperty_new_summary(summary),
        icalproperty_new_uid("1234567890@example.com"),
        (void *)0);

    // Ensure the component is not NULL
    if (component == NULL) {
        return 0;
    }

    // Call the function-under-test
    struct icaltimetype dtstamp = icalcomponent_get_dtstamp(component);

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
