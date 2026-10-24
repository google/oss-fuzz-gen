#include <stdint.h>
#include <stdlib.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_155(const uint8_t *data, size_t size) {
    // Initialize two icalcomponent pointers
    icalcomponent *parent_component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *child_component = icalcomponent_new(ICAL_VEVENT_COMPONENT);

    // Ensure the components are not NULL
    if (parent_component == NULL || child_component == NULL) {
        if (parent_component != NULL) {
            icalcomponent_free(parent_component);
        }
        if (child_component != NULL) {
            icalcomponent_free(child_component);
        }
        return 0;
    }

    // Call the function-under-test
    icalcomponent_add_component(parent_component, child_component);

    // Clean up
    icalcomponent_free(parent_component);
    // Note: No need to free child_component separately as it is now part of parent_component

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

    LLVMFuzzerTestOneInput_155(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
