// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_set_location at icalcomponent.c:1984:6 in icalcomponent.h
// icalcomponent_set_relcalid at icalcomponent.c:2627:6 in icalcomponent.h
// icalcomponent_set_comment at icalcomponent.c:1833:6 in icalcomponent.h
// icalcomponent_set_description at icalcomponent.c:1949:6 in icalcomponent.h
// icalcomponent_set_summary at icalcomponent.c:1798:6 in icalcomponent.h
// icalcomponent_set_uid at icalcomponent.c:1868:6 in icalcomponent.h
#include <iostream>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a dummy icalcomponent
    icalcomponent *comp = icalcomponent_new(ICAL_VEVENT_COMPONENT);

    // Use the input data to set various properties
    const char *inputStr = reinterpret_cast<const char *>(Data);
    size_t strLen = std::min(Size, static_cast<size_t>(255)); // Limit string length
    char *location = new char[strLen + 1];
    char *description = new char[strLen + 1];
    char *comment = new char[strLen + 1];
    char *summary = new char[strLen + 1];
    char *relcalid = new char[strLen + 1];
    char *uid = new char[strLen + 1];

    strncpy(location, inputStr, strLen);
    location[strLen] = '\0';
    strncpy(description, inputStr, strLen);
    description[strLen] = '\0';
    strncpy(comment, inputStr, strLen);
    comment[strLen] = '\0';
    strncpy(summary, inputStr, strLen);
    summary[strLen] = '\0';
    strncpy(relcalid, inputStr, strLen);
    relcalid[strLen] = '\0';
    strncpy(uid, inputStr, strLen);
    uid[strLen] = '\0';

    // Invoke the target functions
    icalcomponent_set_location(comp, location);
    icalcomponent_set_description(comp, description);
    icalcomponent_set_comment(comp, comment);
    icalcomponent_set_summary(comp, summary);
    icalcomponent_set_relcalid(comp, relcalid);
    icalcomponent_set_uid(comp, uid);

    // Clean up
    delete[] location;
    delete[] description;
    delete[] comment;
    delete[] summary;
    delete[] relcalid;
    delete[] uid;
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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    