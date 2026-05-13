// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_new_xstandard at icalcomponent.c:2124:16 in icalcomponent.h
// icalcomponent_new_vreply at icalcomponent.c:2144:16 in icalcomponent.h
// icalcomponent_new_vlocation at icalcomponent.c:2189:16 in icalcomponent.h
// icalcomponent_new_vevent at icalcomponent.c:2094:16 in icalcomponent.h
// icalcomponent_new_vcalendar at icalcomponent.c:2089:16 in icalcomponent.h
// icalcomponent_new_vquery at icalcomponent.c:2139:16 in icalcomponent.h
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
#include <cstdint>
#include <cstdlib>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    // Call icalcomponent_new_vlocation and free the component
    icalcomponent *vlocation = icalcomponent_new_vlocation();
    if (vlocation != nullptr) {
        icalcomponent_free(vlocation);
    }

    // Call icalcomponent_new_vevent and free the component
    icalcomponent *vevent = icalcomponent_new_vevent();
    if (vevent != nullptr) {
        icalcomponent_free(vevent);
    }

    // Call icalcomponent_new_vquery and free the component
    icalcomponent *vquery = icalcomponent_new_vquery();
    if (vquery != nullptr) {
        icalcomponent_free(vquery);
    }

    // Call icalcomponent_new_vreply and free the component
    icalcomponent *vreply = icalcomponent_new_vreply();
    if (vreply != nullptr) {
        icalcomponent_free(vreply);
    }

    // Call icalcomponent_new_xstandard and free the component
    icalcomponent *xstandard = icalcomponent_new_xstandard();
    if (xstandard != nullptr) {
        icalcomponent_free(xstandard);
    }

    // Call icalcomponent_new_vcalendar and free the component
    icalcomponent *vcalendar = icalcomponent_new_vcalendar();
    if (vcalendar != nullptr) {
        icalcomponent_free(vcalendar);
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

        LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    