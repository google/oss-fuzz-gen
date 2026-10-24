#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(icalcomponent_kind)) {
        return 0; // Not enough data to extract icalcomponent_kind
    }

    // Create a dummy icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Extract icalcomponent_kind from input data
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(Data[0]);

    // Try to use icalcomponent_end_component
    icalcompiter end_iter = icalcomponent_end_component(component, kind);
    icalcomponent *end_comp = icalcompiter_deref(&end_iter);
    if (end_comp != NULL) {
        // Do something with end_comp
    }

    // Try to use icalcomponent_begin_component
    icalcompiter begin_iter = icalcomponent_begin_component(component, kind);
    icalcomponent *begin_comp = icalcompiter_deref(&begin_iter);
    if (begin_comp != NULL) {
        // Do something with begin_comp
    }

    // Use icalcomponent_get_current_component
    icalcomponent *current_comp = icalcomponent_get_current_component(component);
    if (current_comp != NULL) {
        // Do something with current_comp
    }

    // Use icalcompiter_prior
    icalcomponent *prior_comp = icalcompiter_prior(&begin_iter);
    if (prior_comp != NULL) {
        // Do something with prior_comp
    }

    // Use icalcompiter_next
    icalcomponent *next_comp = icalcompiter_next(&begin_iter);
    if (next_comp != NULL) {
        // Do something with next_comp
    }

    // Cleanup
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
