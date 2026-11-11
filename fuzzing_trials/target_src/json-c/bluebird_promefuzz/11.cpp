#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "/src/json-c/json_util.h"
#include "/src/json-c/json_object.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdio>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    // Create a temporary file for testing file descriptor functions
    const char *filename = "./dummy_file";
    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        return 0;
    }

    // Write input data to the file
    if (write(fd, Data, Size) != (ssize_t)Size) {
        close(fd);
        return 0;
    }

    // Reset file descriptor position
    lseek(fd, 0, SEEK_SET);

    // Test json_object_from_fd
    struct json_object *obj_from_fd = json_object_from_fd(fd);
    if (obj_from_fd) {
        // Test json_object_to_fd
        json_object_to_fd(fd, obj_from_fd, JSON_C_TO_STRING_PLAIN);

        // Test json_object_set_boolean
        json_object_set_boolean(obj_from_fd, 1);

        // Test json_object_object_add_ex
        struct json_object *new_obj = json_object_new_object();
        json_object_object_add_ex(new_obj, "key", obj_from_fd, JSON_C_OBJECT_ADD_KEY_IS_NEW);

        // Test json_object_to_file
        json_object_to_file(filename, new_obj);

        // Clean up
        json_object_put(new_obj);
    }

    // Reset file descriptor position
    lseek(fd, 0, SEEK_SET);

    // Test json_object_from_fd_ex
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of json_object_from_fd_ex
    struct json_object *obj_from_fd_ex = json_object_from_fd_ex(fd, JSON_C_OPTION_GLOBAL);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (obj_from_fd_ex) {
        json_object_put(obj_from_fd_ex);
    }

    // Close the file descriptor
    close(fd);

    // Remove the temporary file
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
