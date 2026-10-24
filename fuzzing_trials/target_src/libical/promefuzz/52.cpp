// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_get_parent at icalcomponent.c:1270:16 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
// icalcomponent_new_vtodo at icalcomponent.c:2099:16 in icalcomponent.h
// icalcomponent_new_vfreebusy at icalcomponent.c:2114:16 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new VTODO component
    icalcomponent *vtodo = icalcomponent_new_vtodo();
    if (!vtodo) return 0;

    // Clone the VTODO component
    icalcomponent *cloned_vtodo = icalcomponent_clone(vtodo);
    if (cloned_vtodo) {
        // Add the cloned VTODO as a child to the original VTODO
        icalcomponent_add_component(vtodo, cloned_vtodo);
    }

    // Create a new VFREEBUSY component
    icalcomponent *vfreebusy = icalcomponent_new_vfreebusy();
    if (vfreebusy) {
        // Add the VFREEBUSY component as a child to the original VTODO
        icalcomponent_add_component(vtodo, vfreebusy);
    }

    // Get the parent of the cloned VTODO
    icalcomponent *parent_of_cloned = icalcomponent_get_parent(cloned_vtodo);

    // Clean up
    icalcomponent_free(vtodo); // This should recursively free all components

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

        LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    