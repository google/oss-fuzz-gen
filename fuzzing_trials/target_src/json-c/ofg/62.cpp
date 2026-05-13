#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_tokener.h" // Correct path for json_tokener
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    // Create an instance of FuzzedDataProvider to consume fuzzing data
    FuzzedDataProvider fuzzed_data_provider(data, size);
    
    // Consume a random length string to simulate JSON input
    std::string json_input = fuzzed_data_provider.ConsumeRandomLengthString(100);
    
    // Create a json_tokener object using json_tokener_parse
    struct json_tokener *tokener = json_tokener_new();
    if (tokener == nullptr) {
        return 0; // If tokener creation fails, exit early
    }

    // Parse the JSON input to initialize the tokener
    json_object *parsed_obj = json_tokener_parse_ex(tokener, json_input.c_str(), json_input.size());
    
    // Free the parsed json object if not null
    if (parsed_obj != nullptr) {
        json_object_put(parsed_obj);
    }

    // Call the function under test
    json_tokener_free(tokener);

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

    LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
