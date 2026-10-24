// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_remove_property at icalcomponent.c:443:6 in icalcomponent.h
// icalcomponent_get_current_property at icalcomponent.c:506:15 in icalcomponent.h
// icalcomponent_add_property at icalcomponent.c:428:6 in icalcomponent.h
// icalcomponent_as_ical_string_r at icalcomponent.c:245:7 in icalcomponent.h
// icalcomponent_set_description at icalcomponent.c:1949:6 in icalcomponent.h
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
#include <cstdlib>
#include <cstring>
#include <ctime>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_vcalendar_component() {
    return icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
}

static icalproperty* create_random_property() {
    icalproperty_kind kinds[] = {
        ICAL_DESCRIPTION_PROPERTY, ICAL_SUMMARY_PROPERTY, ICAL_LOCATION_PROPERTY
    };
    icalproperty_kind kind = kinds[rand() % (sizeof(kinds) / sizeof(kinds[0]))];
    return icalproperty_new(kind);
}

static void fuzz_icalcomponent_set_description(icalcomponent *comp, const uint8_t *Data, size_t Size) {
    char *description = new char[Size + 1];
    memcpy(description, Data, Size);
    description[Size] = '\0';
    icalcomponent_set_description(comp, description);
    delete[] description;
}

static void fuzz_icalcomponent_add_property(icalcomponent *comp) {
    icalproperty *prop = create_random_property();
    icalcomponent_add_property(comp, prop);
}

static void fuzz_icalcomponent_merge_component(icalcomponent *comp1, icalcomponent *comp2) {
    if (comp1 && comp2) {
        icalcomponent_merge_component(comp1, comp2);
    }
}

static void fuzz_icalcomponent_remove_property(icalcomponent *comp) {
    icalproperty *prop = icalcomponent_get_current_property(comp);
    if (prop) {
        icalcomponent_remove_property(comp, prop);
    }
}

static void fuzz_icalcomponent_as_ical_string_r(icalcomponent *comp) {
    char *ical_str = icalcomponent_as_ical_string_r(comp);
    if (ical_str) {
        std::cout << ical_str << std::endl;
        free(ical_str);
    }
}

static void fuzz_icalcomponent_get_current_property(icalcomponent *comp) {
    icalproperty *prop = icalcomponent_get_current_property(comp);
    if (prop) {
        // Do something with prop if needed
    }
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    srand(time(0));

    icalcomponent *comp1 = create_vcalendar_component();
    icalcomponent *comp2 = create_vcalendar_component();

    if (comp1 && comp2) {
        fuzz_icalcomponent_set_description(comp1, Data, Size);
        fuzz_icalcomponent_add_property(comp1);
        fuzz_icalcomponent_merge_component(comp1, comp2);
        fuzz_icalcomponent_remove_property(comp1);
        fuzz_icalcomponent_as_ical_string_r(comp1);
        fuzz_icalcomponent_get_current_property(comp1);

        icalcomponent_free(comp1);
        // comp2 is already merged into comp1 and should not be freed separately
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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    