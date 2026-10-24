#include <stdint.h>
#include <stdlib.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    // Initialize two icalcomponent objects
    icalcomponent *parent = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *child = icalcomponent_new(ICAL_VEVENT_COMPONENT);

    // Ensure that both components are not NULL
    if (parent == NULL || child == NULL) {
        if (parent != NULL) {
            icalcomponent_free(parent);
        }
        if (child != NULL) {
            icalcomponent_free(child);
        }
        return 0;
    }

    // Call the function under test
    icalcomponent_set_parent(child, parent);

    // Clean up
    icalcomponent_free(child);
    icalcomponent_free(parent);

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

    LLVMFuzzerTestOneInput_148(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
