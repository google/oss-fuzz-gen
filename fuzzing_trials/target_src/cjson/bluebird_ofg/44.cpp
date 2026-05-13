#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
  cJSON *json;
  char *printed_json;
  int prebuffer_size;
  cJSON_bool formatted;

  if (size < 1)
    {
    return 0;
  }

  json = cJSON_ParseWithLength((const char *)data, size);
  if (json == NULL)
    {
    return 0;
  }

  // Use the first byte of data to determine prebuffer_size and formatted
  prebuffer_size = data[0] % 256; // Ensure prebuffer_size is a positive integer
  formatted = (data[0] % 2 == 0) ? 1 : 0; // Toggle formatted based on the first byte

  printed_json = cJSON_PrintBuffered(json, prebuffer_size, formatted);

  if (printed_json != NULL) {
    free(printed_json);
  }


  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_PrintBuffered to cJSON_SetValuestring
  cJSON* ret_cJSON_Parse_ojdwf = cJSON_Parse((const char *)data);
  if (ret_cJSON_Parse_ojdwf == NULL){
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!ret_cJSON_Parse_ojdwf) {
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!printed_json) {
  	return 0;
  }
  char* ret_cJSON_SetValuestring_qqzfi = cJSON_SetValuestring(ret_cJSON_Parse_ojdwf, printed_json);
  if (ret_cJSON_SetValuestring_qqzfi == NULL){
  	return 0;
  }
  // End mutation: Producer.APPEND_MUTATOR
  

  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_SetValuestring to cJSON_PrintPreallocated
  cJSON* ret_cJSON_CreateNumber_imlfu = cJSON_CreateNumber(cJSON_True);
  if (ret_cJSON_CreateNumber_imlfu == NULL){
  	return 0;
  }
  double ret_cJSON_GetNumberValue_xvqzy = cJSON_GetNumberValue(NULL);
  if (ret_cJSON_GetNumberValue_xvqzy < 0){
  	return 0;
  }
  cJSON_bool ret_cJSON_IsInvalid_rwnjw = cJSON_IsInvalid(NULL);
  if (ret_cJSON_IsInvalid_rwnjw < 0){
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!ret_cJSON_CreateNumber_imlfu) {
  	return 0;
  }
  // Ensure dataflow is valid (i.e., non-null)
  if (!ret_cJSON_SetValuestring_qqzfi) {
  	return 0;
  }
  cJSON_bool ret_cJSON_PrintPreallocated_jyzot = cJSON_PrintPreallocated(ret_cJSON_CreateNumber_imlfu, ret_cJSON_SetValuestring_qqzfi, (const int )ret_cJSON_GetNumberValue_xvqzy, ret_cJSON_IsInvalid_rwnjw);
  if (ret_cJSON_PrintPreallocated_jyzot < 0){
  	return 0;
  }
  // End mutation: Producer.APPEND_MUTATOR
  
  cJSON_Delete(json);

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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
