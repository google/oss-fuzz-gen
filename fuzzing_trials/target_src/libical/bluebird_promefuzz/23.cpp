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
#include <cstdint>
#include <cstdlib>
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Create a vJournal component and free it
    icalcomponent *vjournal = icalcomponent_new_vjournal();
    if (vjournal) {
        icalcomponent_free(vjournal);
    }

    // Create an xAvailable component and free it
    icalcomponent *xavailable = icalcomponent_new_xavailable();
    if (xavailable) {
        icalcomponent_free(xavailable);
    }

    // Create an xVote component and free it
    icalcomponent *xvote = icalcomponent_new_xvote();
    if (xvote) {
        icalcomponent_free(xvote);
    }

    // Create a participant component and free it
    icalcomponent *participant = icalcomponent_new_participant();
    if (participant) {
        icalcomponent_free(participant);
    }

    // Create a vAlarm component and free it
    icalcomponent *valarm = icalcomponent_new_valarm();
    if (valarm) {
        icalcomponent_free(valarm);
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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
