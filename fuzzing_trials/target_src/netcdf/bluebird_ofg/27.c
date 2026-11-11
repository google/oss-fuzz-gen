#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern int nc_get_vars_string(int, int, const size_t *, const size_t *, const ptrdiff_t *, char **);

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    if (size < 3 * sizeof(size_t) + sizeof(ptrdiff_t) + sizeof(char *)) {
        return 0;
    }

    int arg1 = (int)data[0];
    int arg2 = (int)data[1];

    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + 2 * sizeof(size_t));

    char *str = (char *)malloc(10);
    if (str == NULL) {
        return 0;
    }
    strncpy(str, "test", 10);

    char **str_array = &str;

    nc_get_vars_string(arg1, arg2, start, count, stride, str_array);

    free(str);
    return 0;
}