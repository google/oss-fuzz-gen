#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <hdf5.h>

// Dummy operator function for H5Aiterate1
herr_t dummy_operator_144(hid_t location_id, const char *attr_name, const H5A_info_t *ainfo, void *op_data) {
    // This is a simple operator function that does nothing
    return 0;
}

int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    // Initialize variables
    hid_t file_id;
    unsigned int index = 0;
    void *op_data = NULL;

    // Ensure that the size is sufficient to create a valid HDF5 file
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use with HDF5
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Create a new HDF5 file using the temporary filename
    file_id = H5Fcreate(tmpl, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    H5Aiterate1(file_id, &index, dummy_operator_144, op_data);

    // Close the HDF5 file
    H5Fclose(file_id);

    // Remove the temporary file
    unlink(tmpl);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_144(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
