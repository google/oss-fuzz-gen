#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cstdlib>
#include <iostream>
#include <openbabel/babelconfig.h>
#include <openbabel/mol.h>
#include <openbabel/obconversion.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  using namespace std;
  using namespace OpenBabel;
  OBConversion obconv;
  OpenBabel::OBMol obmol;
  std::string str(reinterpret_cast<const char *>(Data), Size);

  // FUZZ_INPUT_FORMAT is defined at compile time
  if (!obconv.SetInFormat(FUZZ_INPUT_FORMAT)) {
    abort();
  }
  obconv.ReadString(&obmol, str);
  return 0;
}
