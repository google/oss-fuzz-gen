#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    CURL *curl;
    char *input;
    int output_length;
    char *output;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        // Allocate memory for the input string and ensure it's null-terminated
        input = (char *)malloc(size + 1);
        if (input == NULL) {
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return 0;
        }
        memcpy(input, data, size);
        input[size] = '\0';

        // Call the function-under-test
        output = curl_easy_unescape(curl, input, (int)size, &output_length);

        // Free resources
        if (output) {
            curl_free(output);
        }
        free(input);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
