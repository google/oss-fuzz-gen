#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  // Create a copy of the input data and ensure it is null-terminated
  char *input_data = (char *)malloc(size + 1);
  if (input_data == NULL) {
    return 0;
  }
  memcpy(input_data, data, size);
  input_data[size] = '\0';

  // Call the function-under-test
  cJSON_Minify(input_data);

  // Free the allocated memory

  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_Minify to cJSON_AddRawToObject
  cJSON* ret_cJSON_CreateBool_vmenx = cJSON_CreateBool(cJSON_Number);
  if (ret_cJSON_CreateBool_vmenx == NULL){
  	return 0;
  }
  char* ret_cJSON_GetStringValue_nalcf = cJSON_GetStringValue(NULL);
  if (ret_cJSON_GetStringValue_nalcf == NULL){
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!ret_cJSON_CreateBool_vmenx) {
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!input_data) {
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!ret_cJSON_GetStringValue_nalcf) {
  	return 0;
  }
  cJSON* ret_cJSON_AddRawToObject_dfcsl = cJSON_AddRawToObject(ret_cJSON_CreateBool_vmenx, input_data, ret_cJSON_GetStringValue_nalcf);
  if (ret_cJSON_AddRawToObject_dfcsl == NULL){
  	return 0;
  }
  // End mutation: Producer.APPEND_MUTATOR
  
  free(input_data);

  return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
