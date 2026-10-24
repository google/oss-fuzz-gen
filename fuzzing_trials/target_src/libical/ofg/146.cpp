#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for creating a valid string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the input string and ensure it's null-terminated
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Attempt to parse the input data as an iCalendar string
    icalcomponent *component = icalparser_parse_string(input);
    if (component == NULL) {
        free(input);
        return 0;
    }

    // Set a comment to ensure interaction with the component
    icalcomponent_set_comment(component, "Fuzzing comment");

    // Retrieve and use the comment to ensure code coverage
    const char *retrieved_comment = icalcomponent_get_comment(component);
    if (retrieved_comment != NULL) {
        // Perform a simple operation to utilize the retrieved comment
        size_t comment_length = strlen(retrieved_comment);
        (void)comment_length; // Suppress unused variable warning
    }

    // Clean up
    icalcomponent_free(component);
    free(input);

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

    LLVMFuzzerTestOneInput_146(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
