/*
 * Copyright 2013-2022 Step Function I/O, LLC
 *
 * Licensed to Green Energy Corp (www.greenenergycorp.com) and Step Function I/O
 * LLC (https://stepfunc.io) under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Green Energy Corp and Step Function I/O LLC license
 * this file to you under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996) // don't care about fopen vs fopen_s here
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int main(int argc, char **argv) {
  FILE *fp;
  uint8_t *Data;
  size_t Size;

  if (argc != 2) {
    return 1;
  }
  // opens the file, get its size, and reads it into a buffer
  fp = fopen(argv[1], "rb");
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
  Data = (uint8_t *)malloc(Size);
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

#ifdef _MSC_VER
#pragma warning(pop)
#endif