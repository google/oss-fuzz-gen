#include <exiv2/exiv2.hpp>

#include <cassert>
#include <iomanip>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Invalid files generate a lot of warnings, so switch off logging.
  Exiv2::LogMsg::setLevel(Exiv2::LogMsg::mute);

  Exiv2::XmpParser::initialize();
  ::atexit(Exiv2::XmpParser::terminate);
#ifdef EXV_ENABLE_BMFF
  Exiv2::enableBMFF();
#endif

  try {
    Exiv2::DataBuf data_copy(data, size);
    Exiv2::Image::UniquePtr image = Exiv2::ImageFactory::open(data_copy.c_data(), size);
    assert(image.get() != 0);

    image->readMetadata();
    for (auto &md : image->exifData()) {
      md.print();
      md.print(&image->exifData());
    }
    for (auto &md : image->iptcData()) {
      md.print();
      md.print(&image->exifData());
    }
    for (auto &md : image->xmpData()) {
      md.print();
      md.print(&image->exifData());
    }

    // Print to a std::ostringstream so that the fuzzer doesn't
    // produce lots of garbage on stdout.
    std::ostringstream buffer;
    image->printStructure(buffer, Exiv2::kpsNone);
    image->printStructure(buffer, Exiv2::kpsBasic);
    image->printStructure(buffer, Exiv2::kpsXMP);
    image->printStructure(buffer, Exiv2::kpsRecursive);
    image->printStructure(buffer, Exiv2::kpsIccProfile);
    image->printStructure(buffer, Exiv2::kpsIptcErase);

    image->writeMetadata();

  } catch (...) {
    // Exiv2 throws an exception if the metadata is invalid.
  }

  return 0;
}
