#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstddef>
#include <iostream>

// Assuming the OBU_TYPE is an enum, define it for the context of this fuzzing harness
extern "C" {
    typedef enum {
        OBU_TYPE_0,
        OBU_TYPE_1,
        OBU_TYPE_2,
        OBU_TYPE_3,
        OBU_TYPE_4,
        OBU_TYPE_5,
        OBU_TYPE_6,
        OBU_TYPE_7,
        OBU_TYPE_8,
        OBU_TYPE_9,
        OBU_TYPE_MAX
    } OBU_TYPE;

    // Function-under-test
    const char * aom_obu_type_to_string(OBU_TYPE type);
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract an OBU_TYPE
    if (size < 1) {
        return 0;
    }

    // Extract a value from the data and map it to the OBU_TYPE enum
    OBU_TYPE type = static_cast<OBU_TYPE>(data[0] % OBU_TYPE_MAX);

    // Call the function-under-test
    const char *result = aom_obu_type_to_string(type);

    // Optional: Print the result for debugging purposes
    if (result) {
        std::cout << "OBU Type: " << type << " -> " << result << std::endl;
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
