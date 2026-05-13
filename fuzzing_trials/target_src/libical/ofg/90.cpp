#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    
    // Ensure the data size is sufficient to populate icaldurationtype
    if (size < sizeof(struct icaldurationtype)) {
        icalcomponent_free(component);
        return 0;
    }

    // Create an icaldurationtype from the input data
    struct icaldurationtype duration;
    duration.is_neg = data[0] % 2;  // Use first byte for is_neg
    duration.weeks = data[1];       // Use second byte for weeks
    duration.days = data[2];        // Use third byte for days
    duration.hours = data[3];       // Use fourth byte for hours
    duration.minutes = data[4];     // Use fifth byte for minutes
    duration.seconds = data[5];     // Use sixth byte for seconds

    // Call the function under test
    icalcomponent_set_duration(component, duration);

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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
