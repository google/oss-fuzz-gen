// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_easy_init at easy.c:330:7 in easy.h
// curl_mime_init at mime.c:1202:12 in curl.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_mime_addpart at mime.c:1236:16 in curl.h
// curl_mime_data at mime.c:1295:10 in curl.h
// curl_mime_name at mime.c:1261:10 in curl.h
// curl_mime_data at mime.c:1295:10 in curl.h
// curl_formadd at formdata.c:608:14 in curl.h
// curl_mime_free at mime.c:1104:6 in curl.h
// curl_formfree at formdata.c:664:6 in curl.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <curl/curl.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    // Initialize MIME context
    curl_mime *mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Add a part to the MIME context
    curl_mimepart *part = curl_mime_addpart(mime);
    if (part) {
        // Set part data from input
        curl_mime_data(part, reinterpret_cast<const char *>(Data), Size);

        // Set part name to a substring of input
        curl_mime_name(part, "name");

        // Write data to a file and use it in a MIME part
        write_dummy_file(Data, Size);
        curl_mime_data(part, "./dummy_file", CURL_ZERO_TERMINATED);
    }

    // Use deprecated formadd for comparison
    struct curl_httppost *formpost = nullptr;
    struct curl_httppost *lastptr = nullptr;
    // Ensure the data is null-terminated for curl_formadd
    std::string data_str(reinterpret_cast<const char *>(Data), Size);
    curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "name",
                 CURLFORM_COPYCONTENTS, data_str.c_str(), CURLFORM_END);

    // Clean up
    curl_mime_free(mime);
    curl_formfree(formpost);
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

        LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    