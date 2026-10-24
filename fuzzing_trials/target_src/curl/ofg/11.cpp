#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Initialize a CURLU object
    CURLU *urlp = curl_url();

    // Ensure the CURLU object is not NULL
    if (urlp == NULL) {
        return 0; // Exit if initialization failed
    }

    // Ensure the data is null-terminated to safely use it as a string
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        curl_url_cleanup(urlp);
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Attempt to set the URL using the input data
    CURLUcode result = curl_url_set(urlp, CURLUPART_URL, input, 0);

    // Cleanup
    free(input);
    curl_url_cleanup(urlp);

    // Return 0 to indicate the function executed without crashing
    return result == CURLUE_OK ? 0 : 1;
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
