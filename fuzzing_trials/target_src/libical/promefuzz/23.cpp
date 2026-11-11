// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_as_ical_string at icalcomponent.c:234:7 in icalcomponent.h
// icalcomponent_set_relcalid at icalcomponent.c:2627:6 in icalcomponent.h
// icalcomponent_set_comment at icalcomponent.c:1833:6 in icalcomponent.h
// icalcomponent_set_description at icalcomponent.c:1949:6 in icalcomponent.h
// icalcomponent_get_comment at icalcomponent.c:1845:13 in icalcomponent.h
// icalcomponent_get_timezone at icalcomponent.c:2492:15 in icalcomponent.h
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
#include <cassert>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize an icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    assert(component != nullptr);

    // Use the data to set the description
    char *description = new char[Size + 1];
    std::memcpy(description, Data, Size);
    description[Size] = '\0';
    icalcomponent_set_description(component, description);

    // Retrieve the comment (which should be initially NULL)
    const char *comment = icalcomponent_get_comment(component);
    if (comment != nullptr) {
        std::cout << "Comment: " << comment << std::endl;
    }

    // Use the data to set the comment
    icalcomponent_set_comment(component, description);

    // Retrieve the comment again
    comment = icalcomponent_get_comment(component);
    if (comment != nullptr) {
        std::cout << "Updated Comment: " << comment << std::endl;
    }

    // Use the data to set the RELCALID
    icalcomponent_set_relcalid(component, description);

    // Attempt to retrieve a timezone using part of the data as TZID
    char *tzid = new char[Size + 1];
    std::memcpy(tzid, Data, Size);
    tzid[Size] = '\0';
    icaltimezone *timezone = icalcomponent_get_timezone(component, tzid);

    // Convert the component to an iCal string
    char *ical_string = icalcomponent_as_ical_string(component);
    if (ical_string != nullptr) {
        std::cout << "iCal String: " << ical_string << std::endl;
        // Do not free ical_string as it is managed by the libical library
    }

    // Cleanup
    icalcomponent_free(component);
    delete[] description;
    delete[] tzid;

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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    