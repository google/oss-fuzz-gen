#include <sys/stat.h>
#include <string.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "curl/curl.h"

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    CURLU *url;
    CURLUcode result;
    CURLUPart part;
    unsigned int flags;

    // Initialize the CURLU handle
    url = curl_url();
    if (!url) {
        return 0;
    }

    // Ensure that size is sufficient to extract meaningful data
    if (size < 2) {
        curl_url_cleanup(url);
        return 0;
    }

    // Use the first byte to determine the CURLUPart
    part = static_cast<CURLUPart>(data[0] % (CURLUPART_ZONEID + 1));

    // Use the second byte to determine flags
    flags = static_cast<unsigned int>(data[1]);

    // Use the remaining data as the string input
    const char *input = reinterpret_cast<const char *>(data + 2);
    size_t input_len = size - 2;

    // Ensure the input string is null-terminated
    char *null_terminated_input = static_cast<char *>(malloc(input_len + 1));
    if (!null_terminated_input) {
        curl_url_cleanup(url);
        return 0;
    }
    memcpy(null_terminated_input, input, input_len);
    null_terminated_input[input_len] = '\0';

    // Call the function-under-test
    result = curl_url_set(url, part, null_terminated_input, flags);

    // Clean up
    free(null_terminated_input);
    curl_url_cleanup(url);

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
