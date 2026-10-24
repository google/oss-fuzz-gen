// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
// icalcomponent_new_vlocation at icalcomponent.c:2189:16 in icalcomponent.h
// icalcomponent_new_vcalendar at icalcomponent.c:2089:16 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_new_vtimezone at icalcomponent.c:2119:16 in icalcomponent.h
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>
}

#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    // Step 1: Prepare the environment
    icalcomponent *vcalendar1 = icalcomponent_new_vcalendar();
    icalcomponent *vcalendar2 = icalcomponent_new_vcalendar();
    icalcomponent *vlocation = icalcomponent_new_vlocation();
    icalcomponent *vtimezone = icalcomponent_new_vtimezone();

    // Use the data to decide some operations
    if (Size > 0 && Data[0] % 2 == 0) {
        icalcomponent_set_parent(vlocation, vcalendar1);
    }
    if (Size > 1 && Data[1] % 2 == 0) {
        icalcomponent_set_parent(vtimezone, vcalendar2);
    }

    // Step 2: Invoke the target function
    icalcomponent_merge_component(vcalendar1, vcalendar2);

    // Step 3: Cleanup
    icalcomponent_free(vcalendar1);
    // vcalendar2 is already freed by icalcomponent_merge_component
    if (icalcomponent_get_parent(vlocation) == nullptr) {
        icalcomponent_free(vlocation);
    }
    if (icalcomponent_get_parent(vtimezone) == nullptr) {
        icalcomponent_free(vtimezone);
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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    