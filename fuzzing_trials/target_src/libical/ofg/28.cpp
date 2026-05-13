#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Initialize variables
    icalcomponent *component = nullptr;
    struct icaltimetype start_time;
    struct icaltimetype end_time;

    // Ensure size is sufficient for creating a valid component and time
    if (size < 10) return 0;

    // Create a dummy icalcomponent
    component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (component == nullptr) return 0;

    // Initialize start_time and end_time
    start_time = icaltime_from_timet_with_zone(time(nullptr), 0, nullptr);
    end_time = icaltime_from_timet_with_zone(time(nullptr) + 3600, 0, nullptr);

    // Call the function-under-test
    bool result = icalproperty_recurrence_is_excluded(component, &start_time, &end_time);

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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
