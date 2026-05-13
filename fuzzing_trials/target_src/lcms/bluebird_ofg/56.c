#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"
#include <string.h>

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the first parameter
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Extract the first parameter from the input data
    cmsUInt32Number intent = *(const cmsUInt32Number *)data;

    // Allocate memory for the third parameter
    char description[256];
    memset(description, 0, sizeof(description));  // Initialize the buffer to prevent overflow issues

    // Initialize supportedIntents to a known value
    cmsUInt32Number supportedIntents = 0;

    // Check if the intent is within a reasonable range
    if (intent > 3) {  // Assuming 0 to 3 are valid intents
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsGetSupportedIntents(intent, &supportedIntents, description);

    // Print the result and the description for debugging purposes
    printf("Result: %u, Supported Intents: %u, Description: %s\n", result, supportedIntents, description);

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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
