#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Ensure there's enough data for a key and a number

    // Create a root JSON object
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return 0;

    // Extract a key from the input data
    size_t key_len = data[0] % size; // Ensure key length is within bounds
    if (key_len == 0 || key_len >= size) {
        cJSON_Delete(root);
        return 0;
    }

    char *key = (char *)malloc(key_len + 1);
    if (key == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    memcpy(key, data + 1, key_len);
    key[key_len] = '\0';

    // Extract a number from the input data
    double number = 0.0;
    if (size > key_len + 1) {
        memcpy(&number, data + key_len + 1, sizeof(double) < (size - key_len - 1) ? sizeof(double) : (size - key_len - 1));
    }

    // Add the number to the JSON object with the extracted key
    cJSON *result = cJSON_AddNumberToObject(root, key, number);

    // Clean up
    free(key);
    cJSON_Delete(root);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
