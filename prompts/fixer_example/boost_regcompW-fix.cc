#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include <boost/regex.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider stream(data, size);
  std::string pattern = stream.ConsumeRemainingBytesAsString();
  boost::regex_tW expression;
  int flags = stream.ConsumeIntegral<int>();
  int err = regcompW(&expression, reinterpret_cast<const wchar_t*>(pattern.c_str()), flags); // fix type mismatch
  if (err == 0) {
    regfreeW(&expression);
  }
  return 0;
}
