/* libtheora decoder fuzzer
 * 2019 Guido Vranken
 */

#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <fuzzing/memory.hpp>
#include <theora/theoradec.h>

#define THEORA_NUM_HEADER_PACKETS 3

class TheoraDecoder {
private:
  fuzzing::datasource::Datasource &ds;

  th_setup_info *tsi = nullptr;
  th_dec_ctx *ctx = nullptr;
  th_info ti;
  th_comment tc;

  bool initialize(void);
  void processComments(void) const;
  bool decodePacket(void);
  void writeImage(const th_ycbcr_buffer &image) const;

public:
  TheoraDecoder(fuzzing::datasource::Datasource &ds);
  ~TheoraDecoder(void);
  void Run(void);
};

TheoraDecoder::TheoraDecoder(fuzzing::datasource::Datasource &ds) : ds(ds) {}

TheoraDecoder::~TheoraDecoder(void) {
  /* noret */ th_info_clear(&ti);
  /* noret */ th_comment_clear(&tc);

  if (ctx != nullptr) {
    th_decode_free(ctx);
  }

  if (tsi != nullptr) {
    th_setup_free(tsi);
  }
}

bool TheoraDecoder::initialize(void) {
  /* noret */ th_info_init(&ti);
  /* noret */ th_comment_init(&tc);

  for (int i = 0; i < THEORA_NUM_HEADER_PACKETS; i++) {
    ogg_packet op = {0};

    std::vector<uint8_t> packet;
    /* Fill packet */
    {
      try {
        packet = ds.GetData(0);
      } catch (...) {
        return false;
      }

      op.packet = packet.data();
      op.bytes = packet.size();
      op.b_o_s = 1;
    }

    if (th_decode_headerin(&ti, &tc, &tsi, &op) < 0) {
      return false;
    }
  }

  /* noret */ processComments();

  /* Limit picture resolution to prevent OOMs */
  if (ti.frame_width > 1024 || ti.frame_height > 1024) {
    return false;
  }

  ctx = th_decode_alloc(&ti, tsi);
  if (ctx == nullptr) {
    return false;
  }

  /* noret */ th_setup_free(tsi);
  tsi = nullptr;

  return true;
}

void TheoraDecoder::processComments(void) const {
  for (int i = 0; i < tc.comments; i++) {
    if (tc.user_comments[i]) {
      const int len = tc.comment_lengths[i];
      fuzzing::memory::memory_test(tc.user_comments[i], len);
    }
  }
}

bool TheoraDecoder::decodePacket(void) {
  int err;
  ogg_packet op = {0};

  std::vector<uint8_t> packet;

  /* Fill packet */
  {
    memset(&op, 0, sizeof(op));
    packet = ds.GetData(0);
    op.packet = packet.data();
    op.bytes = packet.size();
    op.granulepos = -1;
    /* TODO op.packetno */
  }

  /* Decode */
  {
    ogg_int64_t granulepos;
    err = th_decode_packetin(ctx, &op, &granulepos);
    if (err < 0) {
      return false;
    }

    /* Verify that granulepos has been set */
    fuzzing::memory::memory_test(granulepos);
  }

  /* Write image data */
  if (err != TH_DUPFRAME) {
    th_ycbcr_buffer ycbcrbuf;
    err = th_decode_ycbcr_out(ctx, ycbcrbuf);
    if (err != 0) {
      return false;
    }

    /* noret */ writeImage(ycbcrbuf);
  }

  return true;
}

void TheoraDecoder::writeImage(const th_ycbcr_buffer &ycbcrbuf) const {
  /* Modelled after examples/player_example.c */

  const th_pixel_fmt px_fmt = ti.pixel_fmt;
  const int y_offset = (ti.pic_x & ~1) + ycbcrbuf[0].stride * (ti.pic_y & ~1);
  const int w = (ti.pic_x + ti.frame_width + 1 & ~1) - (ti.pic_x & ~1);
  const int h = (ti.pic_y + ti.frame_height + 1 & ~1) - (ti.pic_y & ~1);

  if (px_fmt == TH_PF_422) {
    const int uv_offset = (ti.pic_x / 2) + (ycbcrbuf[1].stride) * (ti.pic_y);

    for (int i = 0; i < h; i++) {
      {
        const uint8_t *in_y = ycbcrbuf[0].data + y_offset + ycbcrbuf[0].stride * i;
        fuzzing::memory::memory_test(in_y, w);
      }

      {
        const uint8_t *in_u = ycbcrbuf[1].data + uv_offset + ycbcrbuf[1].stride * i;
        const uint8_t *in_v = ycbcrbuf[2].data + uv_offset + ycbcrbuf[2].stride * i;
        fuzzing::memory::memory_test(in_u, w >> 1);
        fuzzing::memory::memory_test(in_v, w >> 1);
      }
    }
  } else {
    const int uv_offset = (ti.pic_x / 2) + (ycbcrbuf[1].stride) * (ti.pic_y / 2);

    for (int i = 0; i < h; i++) {
      fuzzing::memory::memory_test(ycbcrbuf[0].data + y_offset + ycbcrbuf[0].stride * i, w);
    }

    for (int i = 0; i < h / 2; i++) {
      fuzzing::memory::memory_test(ycbcrbuf[2].data + uv_offset + ycbcrbuf[2].stride * i, w / 2);
      fuzzing::memory::memory_test(ycbcrbuf[1].data + uv_offset + ycbcrbuf[1].stride * i, w / 2);
    }
  }
}

void TheoraDecoder::Run(void) {
  if (initialize() == false) {
    return;
  }

  try {
    size_t numDecoded = 0;
    while (++numDecoded < 10 && ds.Get<bool>() == true) {
      if (decodePacket() == false) {
        break;
      }
    }
  } catch (...) {
  }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzzing::datasource::Datasource ds(data, size);
  TheoraDecoder decoder(ds);

  decoder.Run();

  return 0;
}
