#include <stdint.h>
#include <stddef.h>
#include <libical/ical.h>

extern "C" {

void dummy_callback_188(const icalcomponent *comp, const struct icaltime_span *span, void *data) {
    // Dummy callback function
}

int LLVMFuzzerTestOneInput_188(const uint8_t *data, size_t size) {
    if (size < sizeof(struct icaltimetype) * 2) {
        return 0;
    }

    // Initialize the icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (!component) {
        return 0;
    }

    // Extract two icaltimetype structures from the input data
    struct icaltimetype start_time = *((struct icaltimetype *)data);
    struct icaltimetype end_time = *((struct icaltimetype *)(data + sizeof(struct icaltimetype)));

    // Ensure end_time is after start_time for valid input
    if (icaltime_compare(end_time, start_time) < 0) {
        // Swap start and end times if necessary
        struct icaltimetype temp = start_time;
        start_time = end_time;
        end_time = temp;
    }

    // Call the function-under-test
    icalcomponent_foreach_recurrence(component, start_time, end_time, dummy_callback_188, nullptr);

    // Clean up
    icalcomponent_free(component);

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

    LLVMFuzzerTestOneInput_188(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
