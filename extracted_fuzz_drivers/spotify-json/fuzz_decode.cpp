#include <spotify/json/codec/number.hpp>
#include <spotify/json/codec/object.hpp>
#include <spotify/json/decode.hpp>
#include <spotify/json/encoded_value.hpp>
#include <stdint.h>
#include <string>

namespace {
struct custom_obj {
  std::string val;
};
} // namespace

template <> struct spotify::json::default_codec_t<custom_obj> {
  static codec::object_t<custom_obj> codec() {
    auto codec = codec::object<custom_obj>();
    codec.required("x", &custom_obj::val);
    return codec;
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  custom_obj obj;
  std::string input(reinterpret_cast<const char *>(data), size);
  spotify::json::try_decode(obj, input);
  return 0;
}
