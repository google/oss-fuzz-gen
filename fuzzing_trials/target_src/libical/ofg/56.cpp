#include <stdint.h>
#include <stddef.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Initialize the icalcomponent and icalproperty objects
    icalcomponent *comp = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    icalproperty *prop = icalproperty_new_comment("Sample comment");

    // Ensure that the component and property are not NULL
    if (comp != NULL && prop != NULL) {
        // Add the property to the component
        icalcomponent_add_property(comp, prop);

        // Call the function-under-test
        icalcomponent_remove_property(comp, prop);

        // Clean up
        icalcomponent_free(comp);
        // Note: The property is automatically freed when the component is freed.
    }

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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
