// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// json_object_new_double at json_object.c:1170:21 in json_object.h
// json_object_get_double at json_object.c:1223:8 in json_object.h
// json_object_set_double at json_object.c:1281:5 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_new_double_s at json_object.c:1180:21 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_parse_double at json_util.c:236:5 in json_util.h
// json_object_new_double at json_object.c:1170:21 in json_object.h
// json_object_get_uint64 at json_object.c:872:10 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <cmath>
#include <fuzzer/FuzzedDataProvider.h>
#include <json_util.h>
#include <json_object.h>

extern "C" int LLVMFuzzerTestOneInput_95(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    FuzzedDataProvider fuzzed_data(Data, Size);

    // Fuzz json_object_new_double
    double fuzz_double = fuzzed_data.ConsumeFloatingPoint<double>();
    struct json_object *jso_double = json_object_new_double(fuzz_double);
    if (jso_double) {
        // Fuzz json_object_get_double
        errno = 0;
        double retrieved_double = json_object_get_double(jso_double);
        (void)retrieved_double; // Use the value to avoid unused variable warning

        // Fuzz json_object_set_double
        double new_double = fuzzed_data.ConsumeFloatingPoint<double>();
        int set_result = json_object_set_double(jso_double, new_double);
        (void)set_result; // Use the value to avoid unused variable warning

        json_object_put(jso_double); // Clean up
    }

    // Fuzz json_object_new_double_s
    double fuzz_double_s = fuzzed_data.ConsumeFloatingPoint<double>();
    std::string double_str = fuzzed_data.ConsumeRandomLengthString();
    struct json_object *jso_double_s = json_object_new_double_s(fuzz_double_s, double_str.c_str());
    if (jso_double_s) {
        json_object_put(jso_double_s); // Clean up
    }

    // Fuzz json_parse_double
    double parsed_double;
    std::string double_buf = fuzzed_data.ConsumeRandomLengthString();
    int parse_result = json_parse_double(double_buf.c_str(), &parsed_double);
    (void)parse_result; // Use the value to avoid unused variable warning

    // Fuzz json_object_get_uint64
    struct json_object *jso_uint64 = json_object_new_double(fuzz_double);
    if (jso_uint64) {
        errno = 0;
        uint64_t retrieved_uint64 = json_object_get_uint64(jso_uint64);
        (void)retrieved_uint64; // Use the value to avoid unused variable warning

        json_object_put(jso_uint64); // Clean up
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

        LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    