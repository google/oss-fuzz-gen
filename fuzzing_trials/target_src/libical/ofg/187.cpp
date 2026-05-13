#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

extern "C" {

// Dummy callback function to be used with icalcomponent_foreach_recurrence
void dummy_callback_187(const icalcomponent *comp, const struct icaltime_span *span, void *data) {
    // Do nothing
}

int LLVMFuzzerTestOneInput_187(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Initialize an icalcomponent
    icalcomponent *comp = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (comp == NULL) {
        return 0;
    }

    // Create start and end times
    struct icaltimetype start_time = icaltime_from_timet_with_zone(time(NULL), 0, NULL);
    struct icaltimetype end_time = icaltime_from_timet_with_zone(time(NULL) + 3600, 0, NULL);

    // Call the function-under-test
    icalcomponent_foreach_recurrence(comp, start_time, end_time, dummy_callback_187, NULL);

    // Clean up
    icalcomponent_free(comp);

    return 0;
}

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

    LLVMFuzzerTestOneInput_187(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
