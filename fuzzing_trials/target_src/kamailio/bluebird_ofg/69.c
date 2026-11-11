#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

struct date_body {
    int day;
    int month;
    int year;
};

void free_date(struct date_body *date);

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to fill the date_body structure
    if (size < sizeof(struct date_body)) {
        return 0;
    }

    // Allocate memory for a date_body structure
    struct date_body *date = (struct date_body *)malloc(sizeof(struct date_body));
    if (date == NULL) {
        return 0;
    }

    // Initialize the date_body structure with data from the input
    date->day = data[0] % 31 + 1;   // Ensure day is between 1 and 31
    date->month = data[1] % 12 + 1; // Ensure month is between 1 and 12
    date->year = 1900 + data[2];    // Year starting from 1900

    // Call the function-under-test
    free_date(date);

    // Do not free the allocated memory here, as free_date is assumed to handle it
    // free(date);

    return 0;
}