#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for a null-terminated string
    if (size == 0) return 0;

    // Create a null-terminated string from the input data
    char *relcalid = (char *)malloc(size + 1);
    if (relcalid == NULL) return 0;
    memcpy(relcalid, data, size);
    relcalid[size] = '\0';

    // Create a new icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (component == NULL) {
        free(relcalid);
        return 0;
    }

    // Call the function-under-test
    icalcomponent_set_relcalid(component, relcalid);

    // Additional operations to ensure code coverage
    const char *retrieved_relcalid = icalcomponent_get_relcalid(component);
    if (retrieved_relcalid != NULL) {
        // Perform some operation with the retrieved_relcalid
        printf("Retrieved relcalid: %s\n", retrieved_relcalid);
    }

    // Clean up
    icalcomponent_free(component);
    free(relcalid);

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

    LLVMFuzzerTestOneInput_154(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
