#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Split the input data for two JSON strings
  size_t mid = size / 2;
  const uint8_t *data1 = data;
  size_t size1 = mid;
  const uint8_t *data2 = data + mid;
  size_t size2 = size - mid;

  // Ensure both JSON strings are null-terminated
  char *json_str1 = (char *)malloc(size1 + 1);
  char *json_str2 = (char *)malloc(size2 + 1);
  if (json_str1 == NULL || json_str2 == NULL) {
    free(json_str1);
    free(json_str2);
    return 0;
  }
  memcpy(json_str1, data1, size1);
  json_str1[size1] = '\0';
  memcpy(json_str2, data2, size2);
  json_str2[size2] = '\0';

  // Parse the JSON strings
  cJSON *json1 = cJSON_Parse(json_str1);
  cJSON *json2 = cJSON_Parse(json_str2);


  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_Parse to cJSON_Compare
  cJSON* ret_cJSON_CreateNumber_mpskj = cJSON_CreateNumber(1);
  if (ret_cJSON_CreateNumber_mpskj == NULL){
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!json2) {
  	return 0;
  }
  cJSON_bool ret_cJSON_IsString_wjsgl = cJSON_IsString(json2);
  if (ret_cJSON_IsString_wjsgl < 0){
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!ret_cJSON_CreateNumber_mpskj) {
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!json1) {
  	return 0;
  }
  cJSON_bool ret_cJSON_Compare_ougnj = cJSON_Compare(ret_cJSON_CreateNumber_mpskj, json1, ret_cJSON_IsString_wjsgl);
  if (ret_cJSON_Compare_ougnj < 0){
  	return 0;
  }
  // End mutation: Producer.APPEND_MUTATOR
  

  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_Compare to cJSON_CreateStringArray
  // Ensure dataflow is valid (i.e., non-null)
  if (!json2) {
  	return 0;
  }
  char* ret_cJSON_Print_nyxqj = cJSON_Print(json2);
  if (ret_cJSON_Print_nyxqj == NULL){
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!ret_cJSON_Print_nyxqj) {
  	return 0;
  }
  cJSON* ret_cJSON_CreateStringArray_mgwfl = cJSON_CreateStringArray(&ret_cJSON_Print_nyxqj, ret_cJSON_Compare_ougnj);
  if (ret_cJSON_CreateStringArray_mgwfl == NULL){
  	return 0;
  }
  // End mutation: Producer.APPEND_MUTATOR
  
  free(json_str1);
  free(json_str2);

  if (json1 == NULL || json2 == NULL) {
    cJSON_Delete(json1);
    cJSON_Delete(json2);
    return 0;
  }

  // Compare the two JSON objects
  cJSON_bool case_sensitive = (data[0] % 2 == 0) ? cJSON_True : cJSON_False;
  cJSON_Compare(json1, json2, case_sensitive);

  // Clean up
  cJSON_Delete(json1);
  cJSON_Delete(json2);

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
