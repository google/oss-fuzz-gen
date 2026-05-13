#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    ucl_object_t *obj = ucl_object_new_full(UCL_ARRAY, 0);

    // Ensure that we have some data to work with
    if (size > 0) {
        // Create a temporary string from the data
        char *temp_data = (char *)malloc(size + 1);
        if (temp_data == NULL) {
            return 0; // Exit if memory allocation fails
        }
        memcpy(temp_data, data, size);
        temp_data[size] = '\0';

        // Parse the data into a UCL object
        struct ucl_parser *parser = ucl_parser_new(0);
        if (ucl_parser_add_string(parser, temp_data, size)) {
            ucl_object_t *parsed_obj = ucl_parser_get_object(parser);
            if (parsed_obj != NULL) {
                // If successfully parsed, add to the array
                ucl_array_append(obj, parsed_obj);
                ucl_object_unref(parsed_obj);
            }
        }
        ucl_parser_free(parser);
        free(temp_data);
    }

    // Call the function-under-test
    const ucl_object_t *tail = ucl_array_tail(obj);

    // Clean up
    ucl_object_unref(obj);

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

    LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
