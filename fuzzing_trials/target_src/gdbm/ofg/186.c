#include <stdint.h>
#include <stdio.h>

// Declare the yyparse function
int yyparse();

// Fuzzing function
int LLVMFuzzerTestOneInput_186(const uint8_t *data, size_t size) {
    // Redirect input to a temporary file
    FILE *tempFile = fopen("/tmp/fuzz_input.txt", "wb");
    if (!tempFile) {
        return 0;
    }

    fwrite(data, 1, size, tempFile);
    fclose(tempFile);

    // Redirect stdin to read from the temporary file
    freopen("/tmp/fuzz_input.txt", "rb", stdin);

    // Call the function-under-test
    yyparse();

    // Clean up
    remove("/tmp/fuzz_input.txt");

    return 0;
}