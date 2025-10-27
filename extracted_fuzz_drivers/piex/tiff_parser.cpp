/* By Guido Vranken <guidovranken@gmail.com> */

#include "src/tiff_parser.h"
#include "fuzzing/datasource/datasource.hpp"
#include "shared.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

static piex::TagSet getTagSet(fuzzing::datasource::Datasource &ds) {
  piex::TagSet tagSet;

  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagColorSpace);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagDateTimeOriginal);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagDefaultCropSize);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagExposureTime);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagFnumber);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagFocalLength);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagGps);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagHeight);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagIsoSpeed);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagMakernotes);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kExifTagWidth);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kOlymTagAspectFrame);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kOlymTagCameraSettings);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kOlymTagRawProcessing);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kPanaTagBottomBorder);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kPanaTagIso);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kPanaTagJpegImage);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kPanaTagLeftBorder);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kPanaTagRightBorder);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kPanaTagTopBorder);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kPentaxTagColorSpace);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagArtist);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagBitsPerSample);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagCfaPatternDim);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagCompression);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagDateTime);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagExifIfd);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagImageDescription);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagImageLength);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagImageWidth);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagJpegByteCount);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagJpegOffset);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagMake);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagModel);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagOrientation);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagPhotometric);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagPlanarConfig);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagResolutionUnit);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagRowsPerStrip);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagSamplesPerPixel);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagSoftware);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagStripByteCounts);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagStripOffsets);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagSubFileType);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagSubIfd);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagTileByteCounts);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagTileLength);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagTileOffsets);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagTileWidth);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagXresolution);
  if (ds.Get<bool>())
    tagSet.insert(piex::TiffTags::kTiffTagYresolution);

  return tagSet;
}

static void test_PreviewImageData(const piex::PreviewImageData &preview_image_data) {
  (void)preview_image_data;

  /* TODO test preview_image_data fields for uninitialized memory */
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzzing::datasource::Datasource ds(data, size);

  try {
    const auto tiffData = ds.GetData(0);

    FuzzingStreamInterface stream(tiffData);
    const auto tagSet = getTagSet(ds);
    const auto max_number_ifds = ds.Get<uint16_t>();

    /* XXX To prevent stack overflow. Remove this once upstream is fixed */
    if (max_number_ifds > 100) {
      return 0;
    }

    piex::TiffParser parser(&stream, 0);
    piex::TiffContent tiff_content;
    const bool parseOk = parser.Parse(tagSet, max_number_ifds, &tiff_content);

    if (parseOk && !tiff_content.tiff_directory.empty()) {
      piex::PreviewImageData preview_image_data;

      const bool ok = parser.GetPreviewImageData(tiff_content, &preview_image_data);

      if (ok) {
        test_PreviewImageData(preview_image_data);
      }
    }
  } catch (...) {
  }

  return 0;
}
