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
#include <iostream>
#include <fstream>
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    // Prepare environment and initialize components
    icalcomponent *vtimezone = icalcomponent_new_vtimezone();
    icalcomponent *xdaylight = icalcomponent_new_xdaylight();
    icalcomponent *clone = nullptr;

    // Add xdaylight to vtimezone
    icalcomponent_add_component(vtimezone, xdaylight);

    // Clone the vtimezone component
    clone = icalcomponent_clone(vtimezone);

    // Create a dummy VCALENDAR component for merging
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Add vtimezone to vcalendar1
    icalcomponent_add_component(vcalendar1, vtimezone);

    // Merge vcalendar2 into vcalendar1
    icalcomponent_merge_component(vcalendar1, vcalendar2);

    // Define a dummy callback for foreach_tzid
    auto callback = [](icalparameter *param, void *data) {
        // Dummy callback logic
    };

    // Iterate over TZIDs in the cloned component
    icalcomponent_foreach_tzid(clone, callback, nullptr);

    // Cleanup
    icalcomponent_free(vcalendar1);
    icalcomponent_free(clone);

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
