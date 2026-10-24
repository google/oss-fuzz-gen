#include <stdint.h>
#include <stddef.h>
#include <libical/ical.h>

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
    void icalcomponent_set_duration(icalcomponent *, struct icaldurationtype);
}

extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Create an icalcomponent
    icalcomponent *comp = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (comp == NULL) {
        return 0;
    }

    // Initialize an icaldurationtype with non-NULL values
    struct icaldurationtype duration;
    duration.is_neg = 0; // Positive duration
    duration.weeks = (size > 0) ? data[0] % 52 : 1; // Weeks (0-51)
    duration.days = (size > 1) ? data[1] % 7 : 1;   // Days (0-6)
    duration.hours = (size > 2) ? data[2] % 24 : 1; // Hours (0-23)
    duration.minutes = (size > 3) ? data[3] % 60 : 1; // Minutes (0-59)
    duration.seconds = (size > 4) ? data[4] % 60 : 1; // Seconds (0-59)

    // Call the function under test
    icalcomponent_set_duration(comp, duration);

    // Clean up
    icalcomponent_free(comp);

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

    LLVMFuzzerTestOneInput_89(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
