#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>  // Include for malloc and free
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Ensure there is enough data for two strings and an unsigned int
    if (size < 3) {
        return 0;
    }

    // Split the input data into two strings and an unsigned int
    size_t firstStrLen = data[0] % (size - 2); // Length of the first string
    size_t secondStrLen = data[1] % (size - 2 - firstStrLen); // Length of the second string

    // Ensure the lengths are within the bounds of the data
    if (firstStrLen + secondStrLen + 2 > size) {
        return 0;
    }

    // Extract strings from data
    const char *str1 = (const char *)(data + 2);
    const char *str2 = (const char *)(data + 2 + firstStrLen);

    // Extract options
    unsigned int options = data[2 + firstStrLen + secondStrLen];

    // Null-terminate the strings
    char *nullTermStr1 = (char *)malloc(firstStrLen + 1);
    char *nullTermStr2 = (char *)malloc(secondStrLen + 1);
    if (!nullTermStr1 || !nullTermStr2) {
        free(nullTermStr1);
        free(nullTermStr2);
        return 0;
    }
    memcpy(nullTermStr1, str1, firstStrLen);
    nullTermStr1[firstStrLen] = '\0';
    memcpy(nullTermStr2, str2, secondStrLen);
    nullTermStr2[secondStrLen] = '\0';

    // Call the function-under-test
    int result = sqlite3_strlike(nullTermStr1, nullTermStr2, options);

    // Clean up
    free(nullTermStr1);
    free(nullTermStr2);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_118(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
