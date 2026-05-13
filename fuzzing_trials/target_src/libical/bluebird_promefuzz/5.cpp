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
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icaltime.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalerror.h"

static icalcomponent* create_component_from_data(const uint8_t *Data, size_t Size) {
    // Create a dummy VTODO component
    icalcomponent *comp = icalcomponent_new(ICAL_VTODO_COMPONENT);
    if (!comp) {
        return nullptr;
    }

    // Set some basic properties using the provided data
    if (Size >= sizeof(time_t)) {
        struct icaltimetype dtstart = icaltime_from_timet_with_zone(
            *(const time_t*)Data, 0, nullptr);
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function icalcomponent_set_dtstart with icalcomponent_set_recurrenceid
        icalcomponent_set_recurrenceid(comp, dtstart);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
    }

    return comp;
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    // Create a component from the input data
    icalcomponent *comp = create_component_from_data(Data, Size);
    if (!comp) {
        return 0;
    }

    // Use the icalcomponent_get_due function
    struct icaltimetype due = icalcomponent_get_due(comp);

    // Use the icalcomponent_set_dtend function
    if (Size >= sizeof(time_t)) {
        struct icaltimetype dtend = icaltime_from_timet_with_zone(
            *(const time_t*)Data, 0, nullptr);
        icalcomponent_set_dtend(comp, dtend);
    }

    // Use the icalcomponent_get_dtend function
    struct icaltimetype retrieved_dtend = icalcomponent_get_dtend(comp);

    // Use the icalcomponent_get_recurrenceid function
    struct icaltimetype recurrenceid = icalcomponent_get_recurrenceid(comp);

    // Use the icalcomponent_set_dtstart function
    if (Size >= sizeof(time_t)) {
        struct icaltimetype dtstart = icaltime_from_timet_with_zone(
            *(const time_t*)Data, 0, nullptr);
        icalcomponent_set_dtstart(comp, dtstart);
    }

    // Use the icalcomponent_set_due function
    if (Size >= sizeof(time_t)) {
        struct icaltimetype due_time = icaltime_from_timet_with_zone(
            *(const time_t*)Data, 0, nullptr);
        icalcomponent_set_due(comp, due_time);
    }

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
