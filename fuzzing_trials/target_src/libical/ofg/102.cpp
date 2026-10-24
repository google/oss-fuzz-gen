extern "C" {
#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
}

extern "C" int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Initialize the icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VTODO_COMPONENT);
    if (component == NULL) {
        return 0;
    }

    // Initialize the icaltimetype
    struct icaltimetype due_time;
    due_time.year = 2023;  // Set a default year
    due_time.month = 10;   // Set a default month
    due_time.day = 15;     // Set a default day
    due_time.hour = 12;    // Set a default hour
    due_time.minute = 30;  // Set a default minute
    due_time.second = 0;   // Set a default second
    due_time.is_date = 0;  // Set as date-time
    due_time.zone = icaltimezone_get_utc_timezone(); // Set as UTC time

    // Call the function under test
    icalcomponent_set_due(component, due_time);

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

    LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
