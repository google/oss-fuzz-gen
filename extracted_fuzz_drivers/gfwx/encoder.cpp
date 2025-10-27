/* By Guido Vranken <guidovranken@gmail.com> */

#include "fuzzing/datasource/datasource.hpp"
#include "gfwx.h"
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>

class Image {
public:
  const std::vector<uint8_t> data;
  const size_t width;
  const size_t height;
  const size_t numChannels;
  const size_t totalSize;
  Image(std::vector<uint8_t> data, size_t width, const size_t height, const size_t numChannels) : data(data), width(width), height(height), numChannels(numChannels), totalSize(width * height * numChannels) {}
};

static std::optional<Image> getImage(fuzzing::datasource::Datasource &ds) {
  const size_t numChannels = 3;

  const auto image = ds.GetData(0);
  if (image.empty()) {
    return std::nullopt;
  }
  const auto totalBytesPerChannel = image.size() / numChannels;
  if (totalBytesPerChannel == 0) {
    return std::nullopt;
  }
  const auto divisor = ds.Get<uint64_t>() % totalBytesPerChannel;
  if (divisor == 0) {
    return std::nullopt;
  }
  const auto width = totalBytesPerChannel / divisor;
  if (width == 0) {
    return std::nullopt;
  }
  const auto height = totalBytesPerChannel / width;
  if (height == 0) {
    return std::nullopt;
  }

  const auto totalSize = width * height * numChannels;

  std::vector<uint8_t> imageResized(totalSize);
  memcpy(imageResized.data(), image.data(), totalSize);

  return std::make_optional<Image>(imageResized, width, height, numChannels);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzzing::datasource::Datasource ds(data, size);

  static std::vector<int> encoderChoices({GFWX::EncoderTurbo, GFWX::EncoderFast, GFWX::EncoderContextual});
  static std::vector<int> intentChoices({GFWX::IntentGeneric, GFWX::IntentMono, GFWX::IntentBayerRGGB, GFWX::IntentBayerBGGR, GFWX::IntentBayerGRBG, GFWX::IntentBayerGBRG, GFWX::IntentBayerGeneric, GFWX::IntentRGB, GFWX::IntentRGBA, GFWX::IntentRGBApremult, GFWX::IntentBGR, GFWX::IntentBGRA, GFWX::IntentBGRApremult, GFWX::IntentCMYK});
  static int transform_UYV[] = GFWX_TRANSFORM_UYV;
  static int transform_A710_BGR[] = GFWX_TRANSFORM_A710_BGR;
  static int transform_A710_RGB[] = GFWX_TRANSFORM_A710_RGB;

  static std::vector<int *> transformChoices({transform_UYV, transform_A710_BGR, transform_A710_RGB});

  static std::vector<int> filterChoices({GFWX::FilterLinear, GFWX::FilterCubic});

  try {
    const auto image = getImage(ds);
    if (image == std::nullopt) {
      return 0;
    }

    int layers = 1;
    int channels = image->numChannels;
    int bitDepth = GFWX::BitDepthAuto; // BitDepthAuto selects 8 or 16 based on type
    int quality = (ds.Get<uint16_t>() % 1024) + 1;
    int chromaScale = (ds.Get<uint16_t>() % 1024) + 1;
    int blockSize = ds.Get<uint8_t>() % (GFWX::BlockMax + 1);
    int filter = filterChoices[ds.Get<uint8_t>() % filterChoices.size()];
    int quantization = GFWX::QuantizationScalar;
    int encoder = encoderChoices[ds.Get<uint8_t>() % encoderChoices.size()];
    int intent = intentChoices[ds.Get<uint8_t>() % intentChoices.size()];

    const bool useTransform = ds.Get<bool>();
    int *transform = nullptr;
    if (useTransform) {
      transform = transformChoices[ds.Get<uint8_t>() % transformChoices.size()];
    }

    GFWX::Header header(image->width, image->height, layers, channels, bitDepth, quality, chromaScale, blockSize, filter, quantization, encoder, intent);

    const auto outSize = ds.Get<uint64_t>() % (image->totalSize * 2);
    std::vector<uint8_t> out(outSize);
    const ptrdiff_t size = GFWX::compress(image->data.data(), header, out.data(), out.size(), transform, 0, 0);
    if (size != GFWX::ErrorOverflow) {
      fuzzing::memory::memory_test(out);
    }
  } catch (...) {
  }
  return 0;
}
