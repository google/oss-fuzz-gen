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

static icalcomponent* create_icalcomponent_from_data(const uint8_t *Data, size_t Size) {
    // For simplicity, assume the data is a string representation of an icalcomponent
    char *dataStr = static_cast<char*>(malloc(Size + 1));
    if (!dataStr) {
        return nullptr;
    }
    memcpy(dataStr, Data, Size);
    dataStr[Size] = '\0';

    icalcomponent *comp = icalcomponent_new_from_string(dataStr);
    free(dataStr);
    return comp;
}

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    icalcomponent *comp = create_icalcomponent_from_data(Data, Size);
    if (!comp) {
        return 0;
    }

    // Fuzz icalcomponent_get_uid
    const char *uid = icalcomponent_get_uid(comp);
    if (uid) {
        std::cout << "UID: " << uid << std::endl;
    }

    // Fuzz icalcomponent_get_x_name (assuming this is the correct function)

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from icalcomponent_get_uid to icalcomponent_set_duration using the plateau pool
    struct icaldurationtype duration;
    // Ensure dataflow is valid (i.e., non-null)
    if (!comp) {
    	return 0;
    }
    icalcomponent_set_duration(comp, duration);
    // End mutation: Producer.SPLICE_MUTATOR
    
    const char *x_name = icalcomponent_get_x_name(comp);
    if (x_name) {
        std::cout << "X Name: " << x_name << std::endl;
    }

    // Fuzz icalcomponent_get_relcalid
    const char *relcalid = icalcomponent_get_relcalid(comp);
    if (relcalid) {
        std::cout << "RELCALID: " << relcalid << std::endl;
    }

    // Fuzz icalcomponent_as_ical_string_r
    char *ical_str = icalcomponent_as_ical_string_r(comp);
    if (ical_str) {
        std::cout << "ICAL String: " << ical_str << std::endl;
        free(ical_str);
    }

    // Fuzz icalcomponent_get_description
    const char *description = icalcomponent_get_description(comp);
    if (description) {
        std::cout << "Description: " << description << std::endl;
    }

    // Fuzz icalcomponent_normalize

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from icalcomponent_get_description to icalcomponent_get_dtend
    // Ensure dataflow is valid (i.e., non-null)
    if (!comp) {
    	return 0;
    }
    struct icaltimetype ret_icalcomponent_get_dtend_uwtgi = icalcomponent_get_dtend(comp);
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from icalcomponent_get_dtend to icalcomponent_add_component
    // Ensure dataflow is valid (i.e., non-null)
    if (!comp) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!comp) {
    	return 0;
    }
    icalcomponent_add_component(comp, comp);
    // End mutation: Producer.APPEND_MUTATOR
    
    icalcomponent_normalize(comp);


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from icalcomponent_normalize to icalcomponent_set_dtend
    struct icaltimetype ret_icalcomponent_get_recurrenceid_qzokh = icalcomponent_get_recurrenceid(NULL);
    // Ensure dataflow is valid (i.e., non-null)
    if (!comp) {
    	return 0;
    }
    icalcomponent_set_dtend(comp, ret_icalcomponent_get_recurrenceid_qzokh);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
