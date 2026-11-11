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
#include <cstdint>
#include <cstdarg>
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Use the first byte of data as an icalcomponent_kind
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(Data[0] % ICAL_NUM_COMPONENT_TYPES);

    // Test icalcomponent_new
    icalcomponent *comp_new = icalcomponent_new(kind);
    if (comp_new) {
        icalcomponent_free(comp_new);
    }

    // Test icalcomponent_new_vvoter
    icalcomponent *comp_vvoter = icalcomponent_new_vvoter();
    if (comp_vvoter) {
        icalcomponent_free(comp_vvoter);
    }

    // Test icalcomponent_new_vreply
    icalcomponent *comp_vreply = icalcomponent_new_vreply();
    if (comp_vreply) {
        icalcomponent_free(comp_vreply);
    }

    // Test icalcomponent_new_xvote
    icalcomponent *comp_xvote = icalcomponent_new_xvote();
    if (comp_xvote) {
        icalcomponent_free(comp_xvote);
    }

    // Test icalcomponent_new_vpoll
    icalcomponent *comp_vpoll = icalcomponent_new_vpoll();
    if (comp_vpoll) {
        icalcomponent_free(comp_vpoll);
    }

    // Test icalcomponent_vanew with a variable argument list
    icalcomponent *comp_vanew = icalcomponent_vanew(kind, NULL);
    if (comp_vanew) {
        icalcomponent_free(comp_vanew);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
