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
#include <stdint.h>
#include <stddef.h>
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    // Fuzz icalcomponent_new_vresource
    icalcomponent *vresource = icalcomponent_new_vresource();
    if (vresource) {
        icalcomponent_free(vresource);
    }

    // Fuzz icalcomponent_new_vpatch
    icalcomponent *vpatch = icalcomponent_new_vpatch();
    if (vpatch) {
        icalcomponent_free(vpatch);
    }

    // Fuzz icalcomponent_new_vevent
    icalcomponent *vevent = icalcomponent_new_vevent();
    if (vevent) {
        icalcomponent_free(vevent);
    }

    // Fuzz icalcomponent_new_vquery
    icalcomponent *vquery = icalcomponent_new_vquery();
    if (vquery) {
        icalcomponent_free(vquery);
    }

    // Fuzz icalcomponent_new_vreply
    icalcomponent *vreply = icalcomponent_new_vreply();
    if (vreply) {
        icalcomponent_free(vreply);
    }

    // Fuzz icalcomponent_new_vcalendar
    icalcomponent *vcalendar = icalcomponent_new_vcalendar();
    if (vcalendar) {
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
