#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "curl/curl.h"
#include "/src/curl/include/curl/easy.h"
#include "/src/curl/include/curl/options.h"
#include "/src/curl/include/curl/typecheck-gcc.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize CURL
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    // Prepare dummy file if needed
    FILE *dummyFile = fopen("./dummy_file", "wb");
    if (dummyFile) {
        fwrite(Data, 1, Size, dummyFile);
        fclose(dummyFile);
    }

    // 1. Test curl_easy_pause
    int action = Data[0] % 3; // Random action from first byte
    curl_easy_pause(curl, action);

    // 2. Test curl_easy_ssls_export
    curl_easy_ssls_export(curl, nullptr, nullptr); // Using nullptrs for simplicity

    // 3. Test curl_easy_option_by_id
    if (Size >= sizeof(CURLoption)) {
        CURLoption optionId;
        memcpy(&optionId, Data, sizeof(CURLoption));
        curl_easy_option_by_id(optionId);
    }

    // 4. Test curl_easy_upkeep
    curl_easy_upkeep(curl);

    // 5. Test curl_share_init
    CURLSH *share = curl_share_init();
    if (share) {
        curl_share_cleanup(share);
    }

    // Cleanup
    curl_easy_cleanup(curl);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
