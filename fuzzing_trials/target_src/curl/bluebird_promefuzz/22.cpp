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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>

static size_t dummy_read_callback(char *buffer, size_t size, size_t nitems, void *instream) {
    return size * nitems;
}

static int dummy_seek_callback(void *instream, curl_off_t offset, int origin) {
    return CURL_SEEKFUNC_OK;
}

static void dummy_free_callback(void *ptr) {
    // No operation
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    CURLcode res;
    curl_mime *mime = curl_mime_init(NULL);
    curl_mimepart *part = curl_mime_addpart(mime);

    // Fuzz curl_mime_subparts
    curl_mime *subparts = curl_mime_init(NULL);
    curl_mime_addpart(subparts);
    res = curl_mime_subparts(part, subparts);
    if (res != CURLE_OK) {
        curl_mime_free(subparts);
    }

    // Fuzz curl_mime_filename
    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu", Size);
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
    res = curl_mime_filename(part, filename);
    if (res == CURLE_OK) {
        curl_mime_filename(part, NULL);
    }

    // Fuzz curl_mime_encoder
    const char *encodings[] = {"binary", "8bit", "7bit", "quoted-printable", "base64", NULL};
    for (int i = 0; encodings[i] != NULL; ++i) {
        res = curl_mime_encoder(part, encodings[i]);
    }
    curl_mime_encoder(part, NULL);

    // Fuzz curl_mime_data_cb
    res = curl_mime_data_cb(part, Size, dummy_read_callback, dummy_seek_callback, dummy_free_callback, NULL);

    // Fuzz curl_mime_name
    char name[256];
    snprintf(name, sizeof(name), "name_%zu", Size);
    res = curl_mime_name(part, name);
    if (res == CURLE_OK) {
        curl_mime_name(part, NULL);
    }

    // Fuzz curl_mime_headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    res = curl_mime_headers(part, headers, 1);
    // No need to free headers manually as curl_mime_headers with take_ownership=1 takes care of it

    curl_mime_free(mime);
    remove(filename);

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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
