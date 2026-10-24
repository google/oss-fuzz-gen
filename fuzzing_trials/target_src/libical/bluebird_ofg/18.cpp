#include <string.h>
#include <sys/stat.h>
#include "libical/ical.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to create a valid icalcomponent
    if (size == 0) {
        return 0;
    }

    // Create a temporary buffer to store the input data as a string
    char *inputData = (char *)malloc(size + 1);
    if (inputData == NULL) {
        return 0;
    }
    memcpy(inputData, data, size);
    inputData[size] = '\0';  // Null-terminate the string

    // Initialize an icalcomponent from the input data
    icalcomponent *component = icalparser_parse_string(inputData);

    // Free the input data buffer
    free(inputData);

    if (component == NULL) {
        return 0;
    }

    // Call the function-under-test
    char *icalString = icalcomponent_as_ical_string_r(component);

    // Free the icalcomponent

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from icalcomponent_as_ical_string_r to icalcomponent_new_from_string
    // Ensure dataflow is valid (i.e., non-null)
    if (!icalString) {
    	return 0;
    }
    icalcomponent* ret_icalcomponent_new_from_string_oiutu = icalcomponent_new_from_string(icalString);
    if (ret_icalcomponent_new_from_string_oiutu == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    icalcomponent_free(component);

    // Free the resulting string from the function call
    if (icalString != NULL) {
        free(icalString);
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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
