#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the structure of date_body is defined as follows:
struct date_body {
    int year;
    int month;
    int day;
};

// Function-under-test declaration
void parse_date(char *date_str, char *format, struct date_body *date);

// Fuzzer entry point
int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Ensure there is enough data to split into two strings and a struct
    if (size < 3) {
        return 0;
    }

    // Allocate memory for date_str and format
    size_t half_size = size / 2;
    char *date_str = (char *)malloc(half_size + 1);
    char *format = (char *)malloc(size - half_size + 1);

    if (date_str == NULL || format == NULL) {
        free(date_str);
        free(format);
        return 0;
    }

    // Copy data into date_str and format
    memcpy(date_str, data, half_size);
    date_str[half_size] = '\0';  // Null-terminate the string

    memcpy(format, data + half_size, size - half_size);
    format[size - half_size] = '\0';  // Null-terminate the string

    // Initialize date_body structure
    struct date_body date;
    date.year = 0;
    date.month = 0;
    date.day = 0;

    // Call the function-under-test
    parse_date(date_str, format, &date);

    // Free allocated memory
    free(date_str);
    free(format);

    return 0;
}