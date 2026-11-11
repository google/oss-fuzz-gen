#include <cstdint>
#include <cstdlib>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a valid icaltimetype
    if (size < sizeof(struct icaltimetype)) {
        return 0;
    }

    // Initialize an icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (component == NULL) {
        return 0;
    }

    // Create an icaltimetype from the input data
    struct icaltimetype dtstamp;
    dtstamp.year = (int)(data[0] % 100 + 1900); // Year between 1900 and 1999
    dtstamp.month = (int)(data[1] % 12 + 1);    // Month between 1 and 12
    dtstamp.day = (int)(data[2] % 28 + 1);      // Day between 1 and 28
    dtstamp.hour = (int)(data[3] % 24);         // Hour between 0 and 23
    dtstamp.minute = (int)(data[4] % 60);       // Minute between 0 and 59
    dtstamp.second = (int)(data[5] % 60);       // Second between 0 and 59
    dtstamp.is_date = 0;                        // Not a date-only value
    dtstamp.zone = icaltimezone_get_utc_timezone(); // Use UTC timezone

    // Call the function-under-test
    icalcomponent_set_dtstamp(component, dtstamp);

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

    LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
