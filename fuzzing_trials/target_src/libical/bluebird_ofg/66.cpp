#include <sys/stat.h>
#include "libical/ical.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to create a valid string
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *inputData = (char *)malloc(size + 1);
    if (inputData == NULL) {
        return 0;
    }
    memcpy(inputData, data, size);
    inputData[size] = '\0';

    // Parse the input data into an icalcomponent
    icalcomponent *component = icalparser_parse_string(inputData);

    // Check if the component was successfully created
    if (component != NULL) {
        // Call the function-under-test
        char *icalString = icalcomponent_as_ical_string_r(component);

        // Free the resulting string if it was created
        if (icalString != NULL) {
            free(icalString);
        }

        // Free the icalcomponent
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function icalcomponent_free with icalcomponent_normalize
        icalcomponent_normalize(component);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from icalcomponent_normalize to icalcomponent_set_duration
        // Ensure dataflow is valid (i.e., non-null)
        if (!component) {
        	return 0;
        }
        struct icaldurationtype ret_icalcomponent_get_duration_kcsfr = icalcomponent_get_duration(component);
        // Ensure dataflow is valid (i.e., non-null)
        if (!component) {
        	return 0;
        }
        icalcomponent_set_duration(component, ret_icalcomponent_get_duration_kcsfr);
        // End mutation: Producer.APPEND_MUTATOR
        

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from icalcomponent_set_duration to icalcomponent_set_parent
        icalcomponent* ret_icalcomponent_new_vjournal_nixsl = icalcomponent_new_vjournal();
        if (ret_icalcomponent_new_vjournal_nixsl == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_icalcomponent_new_vjournal_nixsl) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!component) {
        	return 0;
        }
        icalcomponent_set_parent(ret_icalcomponent_new_vjournal_nixsl, component);
        // End mutation: Producer.APPEND_MUTATOR
        
}

    // Free the input data
    free(inputData);

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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
