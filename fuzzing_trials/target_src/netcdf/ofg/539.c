#include <stdint.h>
#include <stddef.h>

extern int nc_set_fill(int, int, int *);

int LLVMFuzzerTestOneInput_539(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 3) {
        return 0;
    }

    int param1 = *((int*)data);
    int param2 = *((int*)(data + sizeof(int)));
    int param3_value = *((int*)(data + 2 * sizeof(int)));
    int *param3 = &param3_value;

    nc_set_fill(param1, param2, param3);

    return 0;
}