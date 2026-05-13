#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Initialize icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VTODO_COMPONENT);
    if (!component) {
        return 0;
    }

    // Initialize icaltimetype
    struct icaltimetype due_time;
    due_time.year = 2023;  // Example year
    due_time.month = 10;   // Example month
    due_time.day = 15;     // Example day
    due_time.hour = 12;    // Example hour
    due_time.minute = 30;  // Example minute
    due_time.second = 0;   // Example second
    due_time.is_date = 0;  // Example is_date
    due_time.zone = icaltimezone_get_utc_timezone(); // Example timezone

    // Call the function-under-test
    icalcomponent_set_due(component, due_time);

    // Use the input data to modify the component
    // For example, set a summary if the size is sufficient
    if (size > 1) {
        char summary[256];
        size_t summary_length = size < 256 ? size : 255;
        memcpy(summary, data, summary_length);
        summary[summary_length] = '\0'; // Ensure null-termination
        icalcomponent_set_summary(component, summary);
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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
