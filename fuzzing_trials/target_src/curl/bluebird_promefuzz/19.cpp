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
#include "/src/curl/include/curl/multi.h"
#include <iostream>
#include <fstream>

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    CURL *easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Use a dummy file if needed by any of the functions
    std::ofstream dummy_file("./dummy_file");
    if (dummy_file.is_open()) {
        dummy_file.write(reinterpret_cast<const char*>(Data), Size);
        dummy_file.close();
    }

    // Fuzz curl_multi_notify_enable
    unsigned int notification = Size > 0 ? Data[0] : 0;
    curl_multi_notify_enable(multi_handle, notification);

    // Fuzz curl_multi_add_handle
    curl_multi_add_handle(multi_handle, easy_handle);

    // Fuzz curl_multi_perform
    int running_handles;
    curl_multi_perform(multi_handle, &running_handles);

    // Fuzz curl_multi_timeout

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from curl_multi_perform to curl_easy_send using the plateau pool
    size_t n;
    // Ensure dataflow is valid (i.e., non-null)
    if (!easy_handle) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!multi_handle) {
    	return 0;
    }
    CURLcode ret_curl_easy_send_etolp = curl_easy_send(easy_handle, (const void *)multi_handle, Size, &n);
    // End mutation: Producer.SPLICE_MUTATOR
    
    long timeout_ms;
    curl_multi_timeout(multi_handle, &timeout_ms);

    // Fuzz curl_multi_setopt
    CURLMoption option = static_cast<CURLMoption>(Size > 1 ? Data[1] : 0);
    curl_multi_setopt(multi_handle, option, nullptr);

    // Fuzz curl_multi_get_offt

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from curl_multi_setopt to curl_strnequal
    // Ensure dataflow is valid (i.e., non-null)
    if (!easy_handle) {
    	return 0;
    }
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function curl_easy_upkeep with curl_easy_perform
    CURLcode ret_curl_easy_upkeep_gzgnj = curl_easy_perform(easy_handle);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    // Ensure dataflow is valid (i.e., non-null)
    if (!easy_handle) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!multi_handle) {
    	return 0;
    }
    int ret_curl_strnequal_jmmiz = curl_strnequal((const char *)easy_handle, (const char *)multi_handle, CURL_VERSION_NTLM_WB);
    if (ret_curl_strnequal_jmmiz < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    CURLMinfo_offt info = static_cast<CURLMinfo_offt>(Size > 2 ? Data[2] : 0);
    curl_off_t value;
    curl_multi_get_offt(multi_handle, info, &value);

    // Cleanup
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function curl_multi_remove_handle with curl_multi_add_handle
    curl_multi_add_handle(multi_handle, easy_handle);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function curl_easy_cleanup with curl_easy_reset
    curl_easy_reset(easy_handle);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    curl_multi_cleanup(multi_handle);

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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
