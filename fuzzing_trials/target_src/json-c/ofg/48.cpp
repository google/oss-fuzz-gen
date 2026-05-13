#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/printbuf.h"

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object with a double value
    double double_value = fuzzed_data.ConsumeFloatingPoint<double>();
    struct json_object *jobj = json_object_new_double(double_value);

    // Create a printbuf
    struct printbuf *pbuf = printbuf_new();
    if (pbuf == nullptr) {
        json_object_put(jobj);
        return 0;
    }

    // Consume integer values for the last two parameters
    int level = fuzzed_data.ConsumeIntegral<int>();
    int flags = fuzzed_data.ConsumeIntegral<int>();

    // Call the function-under-test
    int result = json_object_double_to_json_string(jobj, pbuf, level, flags);

    // Clean up allocated resources
    json_object_put(jobj);
    printbuf_free(pbuf);

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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
