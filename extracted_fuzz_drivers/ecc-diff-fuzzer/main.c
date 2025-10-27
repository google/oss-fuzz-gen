// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

static int runFile(const char *name) {
  FILE *fp;
  uint8_t *Data;
  size_t Size;

  // opens the file, get its size, and reads it into a buffer
  fp = fopen(name, "rb");
  if (fp == NULL) {
    return 2;
  }
  if (fseek(fp, 0L, SEEK_END) != 0) {
    fclose(fp);
    return 2;
  }
  Size = ftell(fp);
  if (Size == (size_t)-1) {
    fclose(fp);
    return 2;
  }
  if (fseek(fp, 0L, SEEK_SET) != 0) {
    fclose(fp);
    return 2;
  }
  Data = malloc(Size);
  if (Data == NULL) {
    fclose(fp);
    return 2;
  }
  if (fread(Data, Size, 1, fp) != 1) {
    fclose(fp);
    return 2;
  }

  // lauch fuzzer
  LLVMFuzzerTestOneInput(Data, Size);
  fclose(fp);
  return 0;
}

int main(int argc, char **argv) {
  DIR *d;
  struct dirent *dir;
  int r = 0;
  int i;

  if (argc != 2) {
    return 1;
  }

  d = opendir(argv[1]);
  if (d == NULL) {
    // try as single file
    return runFile(argv[1]);
    return 0;
  }
  if (chdir(argv[1]) != 0) {
    closedir(d);
    printf("Invalid directory\n");
    return 2;
  }
  while ((dir = readdir(d)) != NULL) {
    // opens the file, get its size, and reads it into a buffer
    if (dir->d_type != DT_REG) {
      continue;
    }
    printf("Running file %s\n", dir->d_name);
    if (runFile(dir->d_name) != 0) {
      printf("Error while running file %s\n", dir->d_name);
    }
  }
  closedir(d);
  printf("Ok : whole directory finished\n");

  return 0;
}
