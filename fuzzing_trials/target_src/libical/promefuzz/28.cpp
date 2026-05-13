// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_new_vavailability at icalcomponent.c:2149:16 in icalcomponent.h
// icalcomponent_new_vagenda at icalcomponent.c:2134:16 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
// icalcomponent_new_xavailable at icalcomponent.c:2154:16 in icalcomponent.h
// icalcomponent_new_vreply at icalcomponent.c:2144:16 in icalcomponent.h
// icalcomponent_new_vevent at icalcomponent.c:2094:16 in icalcomponent.h
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
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    // Create various icalcomponents using the target API functions
    icalcomponent *vagenda = icalcomponent_new_vagenda();
    icalcomponent *vevent = icalcomponent_new_vevent();
    icalcomponent *xavailable = icalcomponent_new_xavailable();
    icalcomponent *vreply = icalcomponent_new_vreply();
    icalcomponent *vavailability = icalcomponent_new_vavailability();

    // Simulate diverse use of the components
    bool vagendaFreed = false;
    bool veventFreed = false;
    bool xavailableFreed = false;
    bool vreplyFreed = false;
    bool vavailabilityFreed = false;

    if (Size > 0) {
        switch (Data[0] % 5) {
            case 0:
                // Perform operations with vagenda
                icalcomponent_free(vagenda);
                vagendaFreed = true;
                break;
            case 1:
                // Perform operations with vevent
                icalcomponent_free(vevent);
                veventFreed = true;
                break;
            case 2:
                // Perform operations with xavailable
                icalcomponent_free(xavailable);
                xavailableFreed = true;
                break;
            case 3:
                // Perform operations with vreply
                icalcomponent_free(vreply);
                vreplyFreed = true;
                break;
            case 4:
                // Perform operations with vavailability
                icalcomponent_free(vavailability);
                vavailabilityFreed = true;
                break;
            default:
                break;
        }
    }

    // Free any components that were not freed in the switch
    if (!vagendaFreed && vagenda) icalcomponent_free(vagenda);
    if (!veventFreed && vevent) icalcomponent_free(vevent);
    if (!xavailableFreed && xavailable) icalcomponent_free(xavailable);
    if (!vreplyFreed && vreply) icalcomponent_free(vreply);
    if (!vavailabilityFreed && vavailability) icalcomponent_free(vavailability);

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

        LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    