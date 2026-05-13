// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_easy_init at easy.c:330:7 in easy.h
// curl_mime_init at mime.c:1202:12 in curl.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_mime_addpart at mime.c:1236:16 in curl.h
// curl_mime_free at mime.c:1104:6 in curl.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_mime_filedata at mime.c:1322:10 in curl.h
// curl_mime_filename at mime.c:1278:10 in curl.h
// curl_mime_data at mime.c:1295:10 in curl.h
// curl_mime_encoder at mime.c:1396:10 in curl.h
// curl_mime_name at mime.c:1261:10 in curl.h
// curl_mime_type at mime.c:1370:10 in curl.h
// curl_mime_free at mime.c:1104:6 in curl.h
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
#include <cstddef>
#include <cstdint>
#include <fstream>

static void initialize_dummy_file() {
    std::ofstream outfile("./dummy_file");
    outfile << "This is a dummy file for testing curl_mime_filedata.";
    outfile.close();
}

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    CURLcode res;
    curl_mime *mime;
    curl_mimepart *part;
    CURL *easy = curl_easy_init();

    if (!easy) {
        return 0;
    }

    mime = curl_mime_init(easy);
    if (!mime) {
        curl_easy_cleanup(easy);
        return 0;
    }

    part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    initialize_dummy_file();

    // Ensure null-termination for string inputs
    std::string input(reinterpret_cast<const char*>(Data), Size);
    input.push_back('\0');

    // Test curl_mime_filedata
    res = curl_mime_filedata(part, "./dummy_file");

    // Test curl_mime_filename
    res = curl_mime_filename(part, input.c_str());

    // Test curl_mime_data
    res = curl_mime_data(part, input.c_str(), Size);

    // Test curl_mime_encoder
    res = curl_mime_encoder(part, input.c_str());

    // Test curl_mime_name
    res = curl_mime_name(part, input.c_str());

    // Test curl_mime_type
    res = curl_mime_type(part, input.c_str());

    // Cleanup
    curl_mime_free(mime);
    curl_easy_cleanup(easy);

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

        LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    