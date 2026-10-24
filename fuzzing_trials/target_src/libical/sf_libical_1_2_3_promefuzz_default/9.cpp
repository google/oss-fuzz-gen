// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_new_vtodo at icalcomponent.c:2099:16 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
// icalcomponent_add_property at icalcomponent.c:428:6 in icalcomponent.h
// icalcomponent_set_dtstamp at icalcomponent.c:1774:6 in icalcomponent.h
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
#include <icalcomponent.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalproperty.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icaltimezone.h>

static void fuzz_icalcomponent_add_property(icalcomponent *component, icalproperty *property) {
    icalcomponent_add_property(component, property);
}

static void fuzz_icalcomponent_merge_component(icalcomponent *comp, icalcomponent *comp_to_merge) {
    icalcomponent_merge_component(comp, comp_to_merge);
}

static icalcomponent* fuzz_icalcomponent_new_vtodo() {
    return icalcomponent_new_vtodo();
}

static void fuzz_icalcomponent_set_parent(icalcomponent *component, icalcomponent *parent) {
    icalcomponent_set_parent(component, parent);
}

static void fuzz_icalcomponent_remove_component(icalcomponent *parent, icalcomponent *child) {
    icalcomponent_remove_component(parent, child);
}

static void fuzz_icalcomponent_set_dtstamp(icalcomponent *comp, struct icaltimetype v) {
    icalcomponent_set_dtstamp(comp, v);
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy file for any file-based operations
    std::ofstream dummy_file("./dummy_file");
    dummy_file.write(reinterpret_cast<const char*>(Data), Size);
    dummy_file.close();

    icalcomponent *comp1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *comp2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Ensure the input data is null-terminated to prevent overflow in string operations
    std::vector<char> dataVec(Data, Data + Size);
    dataVec.push_back('\0');
    icalproperty *prop = icalproperty_new_comment(dataVec.data());

    struct icaltimetype dtstamp;
    dtstamp.year = 2023; // Arbitrary year for fuzzing
    dtstamp.zone = icaltimezone_get_utc_timezone();

    // Fuzz icalcomponent_add_property
    fuzz_icalcomponent_add_property(comp1, prop);

    // Fuzz icalcomponent_merge_component
    fuzz_icalcomponent_merge_component(comp1, comp2);

    // comp2 is freed after merging, so we should not free it again
    comp2 = nullptr;

    // Fuzz icalcomponent_new_vtodo
    icalcomponent *vtodo = fuzz_icalcomponent_new_vtodo();

    // Fuzz icalcomponent_set_parent
    fuzz_icalcomponent_set_parent(vtodo, comp1);

    // Fuzz icalcomponent_remove_component
    fuzz_icalcomponent_remove_component(comp1, vtodo);

    // Fuzz icalcomponent_set_dtstamp
    fuzz_icalcomponent_set_dtstamp(comp1, dtstamp);

    // Cleanup
    // Remove the property from the component before freeing to avoid double-free
    icalcomponent_remove_property(comp1, prop);
    icalproperty_free(prop);
    icalcomponent_free(comp1);
    if (comp2) {
        icalcomponent_free(comp2);
    }
    icalcomponent_free(vtodo);

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

        LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    