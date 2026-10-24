#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
  // Ensure that the input size is sufficient for our needs
  if (size < sizeof(hid_t) + sizeof(H5_index_t) + sizeof(H5_iter_order_t) + sizeof(hsize_t)) {
    return 0;
  }

  // Extract values from the input data
  size_t offset = 0;
  
  // Extract hid_t from data
  hid_t loc_id = *(const hid_t *)(data + offset);
  offset += sizeof(hid_t);

  // Extract a null-terminated string for the name
  const char *name = "test_name"; // Use a fixed name for simplicity

  // Extract H5_index_t from data
  H5_index_t idx_type = *(const H5_index_t *)(data + offset);
  offset += sizeof(H5_index_t);

  // Extract H5_iter_order_t from data
  H5_iter_order_t order = *(const H5_iter_order_t *)(data + offset);
  offset += sizeof(H5_iter_order_t);

  // Extract hsize_t from data
  hsize_t n = *(const hsize_t *)(data + offset);
  offset += sizeof(hsize_t);

  // Prepare H5A_info_t structure
  H5A_info_t ainfo;

  // Use a fixed hid_t for the lapl_id
  hid_t lapl_id = H5P_DEFAULT;

  // Call the function-under-test
  herr_t result = H5Aget_info_by_idx(loc_id, name, idx_type, order, n, &ainfo, lapl_id);

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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
