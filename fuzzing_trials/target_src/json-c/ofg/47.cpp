#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/printbuf.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a random length string for json data
    std::string json_str = fuzzed_data.ConsumeRandomLengthString(100);
    struct json_object *jobj = json_tokener_parse(json_str.c_str());

    // Create a print buffer
    struct printbuf *pbuf = printbuf_new();

    // Consume integers for the other parameters
    int arg1 = fuzzed_data.ConsumeIntegral<int>();
    int arg2 = fuzzed_data.ConsumeIntegral<int>();

    // Call the function-under-test
    if (jobj != NULL && pbuf != NULL) {
        json_object_double_to_json_string(jobj, pbuf, arg1, arg2);
    }

    // Free allocated resources
    if (jobj != NULL) {
        json_object_put(jobj);
    }
    if (pbuf != NULL) {
        printbuf_free(pbuf);
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
