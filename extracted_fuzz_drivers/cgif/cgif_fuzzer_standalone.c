#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *pData, size_t size);

int main(int argn, char **pArgs) {
  FILE *pFile;

  if (argn != 2) {
    fprintf(stderr, "invalid number of arguments\n");
    return 1;
  }
  pFile = fopen(pArgs[1], "rb");
  if (pFile == NULL) {
    fprintf(stderr, "failed to open file\n");
    return 2;
  }
  // get size of input
  fseek(pFile, 0, SEEK_END);
  const long size = ftell(pFile);
  fseek(pFile, 0, SEEK_SET);
  // read input
  uint8_t *pData = malloc(size);
  if (pData == NULL) {
    fclose(pFile);
    return 3;
  }
  size_t r = fread(pData, size, 1, pFile);
  fclose(pFile);
  if (r != 1) {
    fprintf(stderr, "read failed\n");
    free(pData);
    return 4;
  }
  // test input
  LLVMFuzzerTestOneInput(pData, size);
  free(pData);
  return 0;
}
