// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_get_comment at icalcomponent.c:1845:13 in icalcomponent.h
// icalcomponent_get_summary at icalcomponent.c:1810:13 in icalcomponent.h
// icalcomponent_set_uid at icalcomponent.c:1868:6 in icalcomponent.h
// icalcomponent_get_location at icalcomponent.c:1996:13 in icalcomponent.h
// icalcomponent_get_relcalid at icalcomponent.c:2639:13 in icalcomponent.h
// icalcomponent_clone at icalcomponent.c:137:16 in icalcomponent.h
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
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_dummy_icalcomponent() {
    // Create a dummy icalcomponent for testing
    icalcomponent *comp = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (comp) {
        // Set some properties to explore more states
        icalcomponent_set_uid(comp, "dummy-uid");
        icalproperty *summary = icalproperty_new_summary("Dummy Summary");
        if (summary) {
            icalcomponent_add_property(comp, summary);
        }
        icalproperty *location = icalproperty_new_location("Dummy Location");
        if (location) {
            icalcomponent_add_property(comp, location);
        }
        icalproperty *comment = icalproperty_new_comment("Dummy Comment");
        if (comment) {
            icalcomponent_add_property(comp, comment);
        }
        icalproperty *relcalid = icalproperty_new_relcalid("Dummy RelCalId");
        if (relcalid) {
            icalcomponent_add_property(comp, relcalid);
        }
    }
    return comp;
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a dummy icalcomponent
    icalcomponent *comp = create_dummy_icalcomponent();
    if (!comp) {
        return 0;
    }

    // Clone the component
    icalcomponent *clone = icalcomponent_clone(comp);
    if (clone) {
        icalcomponent_free(clone);
    }

    // Get various properties
    const char *comment = icalcomponent_get_comment(comp);
    const char *location = icalcomponent_get_location(comp);
    const char *relcalid = icalcomponent_get_relcalid(comp);
    const char *summary = icalcomponent_get_summary(comp);

    // Set a new UID using fuzzer data
    char uid[Size + 1];
    memcpy(uid, Data, Size);
    uid[Size] = '\0';
    icalcomponent_set_uid(comp, uid);

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

        LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    