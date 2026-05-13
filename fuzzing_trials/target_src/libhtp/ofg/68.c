#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include string.h for memcpy function
#include "/src/libhtp/htp/htp.h"  // Include the correct header file path where htp_uri_t is defined

// Function to create a bstr from a given data and size
bstr *create_bstr_68(const uint8_t *data, size_t size) {
    bstr *b = (bstr *)malloc(sizeof(bstr));
    if (b == NULL) {
        return NULL;
    }
    b->len = size;
    b->size = size;
    b->realptr = (unsigned char *)malloc(size);
    if (b->realptr == NULL) {
        free(b);
        return NULL;
    }
    memcpy(b->realptr, data, size);
    return b;
}

// Function to free a bstr
void free_bstr(bstr *b) {
    if (b != NULL) {
        free(b->realptr);
        free(b);
    }
}

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    htp_uri_t *uri = (htp_uri_t *)malloc(sizeof(htp_uri_t));
    if (uri == NULL) {
        return 0;
    }

    // Initialize the uri structure with some non-NULL values
    uri->scheme = create_bstr_68(data, size);
    uri->hostname = create_bstr_68(data, size);
    uri->port = create_bstr_68((const uint8_t *)"80", 2); // Assigning a common port number as string
    uri->port_number = 80; // Assigning a common port number
    uri->path = create_bstr_68(data, size);
    uri->query = create_bstr_68(data, size);
    uri->fragment = create_bstr_68(data, size);
    uri->username = create_bstr_68(data, size);
    uri->password = create_bstr_68(data, size);

    // Call the function under test
    htp_uri_free(uri);

    // Free the allocated memory for bstr
    free_bstr(uri->scheme);
    free_bstr(uri->hostname);
    free_bstr(uri->port);
    free_bstr(uri->path);
    free_bstr(uri->query);
    free_bstr(uri->fragment);
    free_bstr(uri->username);
    free_bstr(uri->password);

    // Free the allocated memory for uri
    free(uri);

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

    LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
