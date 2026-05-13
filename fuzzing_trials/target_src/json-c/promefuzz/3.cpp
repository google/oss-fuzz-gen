// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// json_object_new_array at json_object.c:1509:21 in json_object.h
// json_object_get_array at json_object.c:1527:20 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// array_list_add at arraylist.c:175:5 in arraylist.h
// json_object_put at json_object.c:272:5 in json_object.h
// array_list_sort at arraylist.c:190:6 in arraylist.h
// array_list_bsearch at arraylist.c:195:7 in arraylist.h
// array_list_length at arraylist.c:201:8 in arraylist.h
// json_object_put at json_object.c:272:5 in json_object.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include <arraylist.h>
#include <json_object.h>
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static int compare_function(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static void free_function(void *data) {
    free(data);
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a json_object of type array
    struct json_object *jobj = json_object_new_array();
    if (!jobj) {
        return 0;
    }

    // Retrieve the array_list from the json_object
    struct array_list *arr = json_object_get_array(jobj);
    if (!arr) {
        json_object_put(jobj);
        return 0;
    }

    // Set the free function for the array_list
    arr->free_fn = free_function;

    // Add elements to the array_list
    char *data = (char *)malloc(Size + 1);
    if (!data) {
        json_object_put(jobj);
        return 0;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    if (array_list_add(arr, data) == -1) {
        free(data);
        json_object_put(jobj);
        return 0;
    }

    // Sort the array_list
    array_list_sort(arr, compare_function);

    // Perform binary search on the array_list
    void *found = array_list_bsearch((const void **)&data, arr, compare_function);

    // Get the length of the array_list
    size_t length = array_list_length(arr);

    // Free the json_object, which also frees the array_list
    json_object_put(jobj);

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

        LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    