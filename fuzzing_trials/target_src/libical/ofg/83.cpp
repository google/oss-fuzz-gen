#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract meaningful values
    if (size < sizeof(int) * 6) {
        return 0;
    }

    // Initialize variables for icaltimetype
    int year = (int)data[0] + 1900; // Year range from 1900 to 2155
    int month = (int)data[1] % 12 + 1; // Month range from 1 to 12
    int day = (int)data[2] % 31 + 1; // Day range from 1 to 31
    int hour = (int)data[3] % 24; // Hour range from 0 to 23
    int minute = (int)data[4] % 60; // Minute range from 0 to 59
    int second = (int)data[5] % 60; // Second range from 0 to 59

    // Create a icaltimetype struct
    struct icaltimetype dtend = icaltime_from_day_of_year(day, year);

    // Set the time
    dtend.hour = hour;
    dtend.minute = minute;
    dtend.second = second;

    // Create an icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);

    // Call the function-under-test
    icalcomponent_set_dtend(component, dtend);

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

    LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
