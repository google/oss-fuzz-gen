// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_easy_init at easy.c:330:7 in easy.h
// curl_mime_init at mime.c:1202:12 in curl.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_mime_addpart at mime.c:1236:16 in curl.h
// curl_mime_free at mime.c:1104:6 in curl.h
// curl_easy_cleanup at easy.c:838:6 in easy.h
// curl_mime_filedata at mime.c:1322:10 in curl.h
// curl_mime_name at mime.c:1261:10 in curl.h
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
#include <typecheck-gcc.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    curl_mime *mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a new MIME part
    curl_mimepart *part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Write data to a dummy file
    write_dummy_file(Data, Size);

    // Fuzz curl_mime_filedata
    CURLcode res = curl_mime_filedata(part, "./dummy_file");

    // Fuzz curl_mime_name
    char name[256];
    snprintf(name, sizeof(name), "name_%zu", Size);
    res = curl_mime_name(part, name);

    // Clean up
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    // Remove the dummy file
    remove("./dummy_file");

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

        LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    