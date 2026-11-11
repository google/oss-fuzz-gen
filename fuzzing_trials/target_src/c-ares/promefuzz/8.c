// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_init at ares_init.c:67:5 in ares.h
// ares_cancel at ares_cancel.c:34:6 in ares.h
// ares_set_socket_callback at ares_socket.c:398:6 in ares.h
// ares_set_socket_configure_callback at ares_socket.c:408:6 in ares.h
// ares_set_socket_functions at ares_set_socket_functions.c:579:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// Custom socket functions
static ares_socket_t custom_asocket(int domain, int type, int protocol, void *user_data) {
    return socket(domain, type, protocol);
}

static int custom_aclose(ares_socket_t sock, void *user_data) {
    return close(sock);
}

static int custom_aconnect(ares_socket_t sock, const struct sockaddr *address, ares_socklen_t address_len, void *user_data) {
    return connect(sock, address, address_len);
}

static ares_ssize_t custom_arecvfrom(ares_socket_t sock, void *buffer, size_t length, int flags,
                                     struct sockaddr *address, ares_socklen_t *address_len, void *user_data) {
    return recvfrom(sock, buffer, length, flags, address, address_len);
}

static ares_ssize_t custom_asendv(ares_socket_t sock, const struct iovec *vec, int count, void *user_data) {
    // Dummy implementation
    return -1;
}

// Custom socket callback functions
static int custom_socket_create_callback(ares_socket_t sock, int type, void *user_data) {
    return ARES_SUCCESS;
}

static int custom_socket_configure_callback(ares_socket_t sock, int type, void *user_data) {
    return ARES_SUCCESS;
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    ares_channel channel;
    struct ares_socket_functions socket_funcs = {
        .asocket = custom_asocket,
        .aclose = custom_aclose,
        .aconnect = custom_aconnect,
        .arecvfrom = custom_arecvfrom,
        .asendv = custom_asendv
    };

    // Initialize the channel
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Cancel any ongoing DNS lookups
    ares_cancel(channel);

    // Set socket callback
    ares_set_socket_callback(channel, custom_socket_create_callback, NULL);

    // Set socket configure callback
    ares_set_socket_configure_callback(channel, custom_socket_configure_callback, NULL);

    // Set socket functions
    ares_set_socket_functions(channel, &socket_funcs, NULL);

    // Cleanup
    ares_destroy(channel);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
