#include <aspell.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <aspell/common/config.hpp>
#include <aspell/common/info.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  Config *c = new Config();
  if (fuzzed_data.ConsumeBool()) {
    c->dictionary_encoding_utf8 = fuzzed_data.ConsumeIntegral<unsigned int>();
  }
  if (fuzzed_data.ConsumeBool()) {
    c->encoding = reinterpret_cast<const char *>(fuzzed_data.ConsumeRemainingBytes<uint8_t>().data());
  }

  void acommon::MDInfoListofLists::clear(Config *);
  acommon::MDInfoListofLists md_info_listof_lists;
  md_info_listof_lists.clear(c);
  delete c;
  return 0;
}
