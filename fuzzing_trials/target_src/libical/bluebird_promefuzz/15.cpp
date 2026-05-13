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
#include <fstream>
#include <cstring>
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalcomponent.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icaltimezone.h"

static void fuzz_icalcomponent_get_timezone(icalcomponent *comp, const std::string &input) {
    // Attempt to retrieve timezone using input as TZID
    icaltimezone *timezone = icalcomponent_get_timezone(comp, input.c_str());
    if (timezone) {
        const char *tzid = icaltimezone_get_tzid(timezone);
        if (tzid) {
            std::cout << "Timezone ID: " << tzid << std::endl;
        }
    }
}

static void fuzz_icalcomponent_get_location(icalcomponent *comp) {
    // Retrieve location property
    const char *location = icalcomponent_get_location(comp);
    if (location) {
        std::cout << "Location: " << location << std::endl;
    }
}

static void fuzz_icalcomponent_get_uid(icalcomponent *comp) {
    // Retrieve UID property
    const char *uid = icalcomponent_get_uid(comp);
    if (uid) {
        std::cout << "UID: " << uid << std::endl;
    }
}

static void fuzz_icalcomponent_get_description(icalcomponent *comp) {
    // Retrieve description property
    const char *description = icalcomponent_get_description(comp);
    if (description) {
        std::cout << "Description: " << description << std::endl;
    }
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    // Ensure the input data is null-terminated
    std::string input(reinterpret_cast<const char *>(Data), Size);

    // Create a new icalcomponent from the input string
    icalcomponent *comp = icalcomponent_new_from_string(input.c_str());
    if (comp) {
        // Fuzz each target function with the created component
        fuzz_icalcomponent_get_timezone(comp, input);
        fuzz_icalcomponent_get_location(comp);
        fuzz_icalcomponent_get_uid(comp);
        fuzz_icalcomponent_get_description(comp);

        // Clean up the component
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function icalcomponent_free with icalcomponent_convert_errors
        icalcomponent_convert_errors(comp);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from icalcomponent_convert_errors to icalcomponent_set_uid
        // Ensure dataflow is valid (i.e., non-null)
        if (!comp) {
        	return 0;
        }
        char* ret_icalcomponent_as_ical_string_r_azwgg = icalcomponent_as_ical_string_r(comp);
        if (ret_icalcomponent_as_ical_string_r_azwgg == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!comp) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_icalcomponent_as_ical_string_r_azwgg) {
        	return 0;
        }
        icalcomponent_set_uid(comp, ret_icalcomponent_as_ical_string_r_azwgg);
        // End mutation: Producer.APPEND_MUTATOR
        
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
