#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/json_util.h"

extern "C" int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Extract a boolean value from the fuzzed data
    json_bool bool_value = fuzzed_data.ConsumeBool();

    // Create a JSON object with the boolean value
    struct json_object *json_obj = json_object_new_boolean(bool_value);

    // Extract a string from the fuzzed data with a reasonable length limit
    std::string json_string = fuzzed_data.ConsumeRandomLengthString(1024);

    // Ensure the string is not empty before attempting to parse
    if (!json_string.empty()) {
        // Attempt to parse the string as a JSON object
        struct json_object *parsed_obj = json_tokener_parse(json_string.c_str());

        // If parsing was successful, perform operations on the parsed object
        if (parsed_obj != nullptr) {
            // Add the boolean JSON object to the parsed JSON object
            json_object_object_add(parsed_obj, "bool_value", json_obj);

            // Serialize the JSON object back to a string
            const char *serialized = json_object_to_json_string(parsed_obj);

            // Clean up the parsed JSON object
            json_object_put(parsed_obj);
        } else {
            // Clean up the boolean JSON object if parsing failed
            json_object_put(json_obj);
        }
    } else {
        // Clean up the boolean JSON object if the string is empty
        json_object_put(json_obj);
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

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
