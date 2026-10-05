/*
  Copyright (c) DataStax, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <gtest/gtest.h>

#include "unit.hpp"

#include <string.h>

#include "batch_request.hpp"
#include "buffer.hpp"
#include "crc.hpp"
#include "driver_config.hpp"
#include "decoder.hpp"
#include "frame.hpp"
#include "protocol.hpp"
#include "query_request.hpp"
#include "request_callback.hpp"
#include "utils.hpp"

using datastax::internal::core::Buffer;
using datastax::internal::core::BufferVec;
using datastax::internal::core::FrameCodec;
using datastax::internal::core::FrameDecoder;
using datastax::internal::core::FRAME_COMPRESSION_LZ4;
using datastax::internal::core::FRAME_COMPRESSION_NONE;
using datastax::internal::core::FrameCompression;
using datastax::internal::core::compute_crc24;
using datastax::internal::core::compute_crc32;
using datastax::internal::core::ProtocolVersion;

class FrameUnitTest : public Unit {
protected:
  static void expect_bytes(const String& expected, const char* actual, size_t actual_size) {
    ASSERT_EQ(expected.size(), actual_size);
    EXPECT_EQ(0, memcmp(expected.data(), actual, actual_size));
  }

  static String payload(size_t size, char seed = 'a') {
    String s;
    s.reserve(size);
    for (size_t i = 0; i < size; ++i) {
      s.push_back(static_cast<char>(seed + (i % 26)));
    }
    return s;
  }

  /**
   * A byte string shaped like a protocol v5 envelope: the 9 byte header whose
   * trailing int32 is the body length, followed by that many body bytes.
   *
   * Payloads that span several frames must be envelope shaped, because that is
   * how the decoder finds the end of the payload: the self contained flag is
   * clear on every frame of a multi frame message, including the last one.
   */
  static String envelope(size_t total_size, char seed = 'a') {
    String s;
    if (total_size < CASS_HEADER_SIZE_V3) {
      return payload(total_size, seed);
    }
    const size_t body = total_size - CASS_HEADER_SIZE_V3;
    s.push_back(static_cast<char>(0x85)); // version, response
    s.push_back(static_cast<char>(0x00)); // flags
    s.push_back(static_cast<char>(0x00)); // stream
    s.push_back(static_cast<char>(0x01));
    s.push_back(static_cast<char>(0x08)); // opcode RESULT
    for (int i = 3; i >= 0; --i) {
      s.push_back(static_cast<char>((body >> (8 * i)) & 0xFF));
    }
    s.append(payload(body, seed));
    return s;
  }

  /** The number of frames a payload of the given size occupies. */
  static size_t frame_count(size_t payload_size, size_t overhead) {
    if (payload_size == 0) return 1;
    return (payload_size + FrameCodec::MAX_PAYLOAD_LENGTH - 1) / FrameCodec::MAX_PAYLOAD_LENGTH;
  }

  /** The self contained flag of the nth frame header in an encoded payload. */
  static bool frame_is_self_contained(const String& framed, size_t header_size,
                                      size_t uncompressed_header_fields, size_t index,
                                      FrameCompression compression) {
    size_t offset = 0;
    for (size_t i = 0; i < index; ++i) {
      uint64_t packed = 0;
      for (int b = uncompressed_header_fields - 1; b >= 0; --b) {
        packed = (packed << 8) | static_cast<uint8_t>(framed[offset + b]);
      }
      size_t payload_length = static_cast<size_t>(packed & 0x1FFFF);
      const size_t bit = compression == FRAME_COMPRESSION_LZ4 ? 34 : 17;
      const bool self_contained = (packed & (static_cast<uint64_t>(1) << bit)) != 0;
      // A self contained frame is always the last one, so nothing follows.
      if (self_contained) {
        EXPECT_LT(i + 1, index) << "self contained frame " << i << " is not the last frame";
      }
      offset += header_size + payload_length + FrameCodec::TRAILER_SIZE;
    }
    uint64_t packed = 0;
    for (int b = uncompressed_header_fields - 1; b >= 0; --b) {
      packed = (packed << 8) | static_cast<uint8_t>(framed[offset + b]);
    }
    const size_t bit = compression == FRAME_COMPRESSION_LZ4 ? 34 : 17;
    return (packed & (static_cast<uint64_t>(1) << bit)) != 0;
  }
};

// The reference values below were produced with the DataStax Python driver's
// frame segment implementation.
TEST_F(FrameUnitTest, Crc24CheckValue) {
  EXPECT_EQ(0x4b3f02u, compute_crc24("123456789", 9));
}

TEST_F(FrameUnitTest, Crc32CheckValue) {
  EXPECT_EQ(0xe2a261a7u, compute_crc32("123456789", 9));
}

TEST_F(FrameUnitTest, ReferenceFrameBytes) {
  const String body = payload(50);
  const String framed = FrameCodec::encode(body);

  // 6 byte header + 50 byte payload + 4 byte trailer.
  ASSERT_EQ(50u + FrameCodec::OVERHEAD, framed.size());
  // Payload length 50 with the self contained flag set, little-endian.
  EXPECT_EQ(0x32, static_cast<uint8_t>(framed[0]));
  EXPECT_EQ(0x00, static_cast<uint8_t>(framed[1]));
  EXPECT_EQ(0x02, static_cast<uint8_t>(framed[2]));
  // CRC24 of the header.
  EXPECT_EQ(0xa5, static_cast<uint8_t>(framed[3]));
  EXPECT_EQ(0xff, static_cast<uint8_t>(framed[4]));
  EXPECT_EQ(0xee, static_cast<uint8_t>(framed[5]));
  EXPECT_EQ(0x13, static_cast<uint8_t>(framed[56]));
  EXPECT_EQ(0xbd, static_cast<uint8_t>(framed[57]));
  EXPECT_EQ(0x8c, static_cast<uint8_t>(framed[58]));
  EXPECT_EQ(0x4f, static_cast<uint8_t>(framed[59]));
}

TEST_F(FrameUnitTest, RoundTripContiguous) {
  for (size_t size = 0; size < 300; ++size) {
    const String body = payload(size);
    const String framed = FrameCodec::encode(body);

    FrameDecoder decoder;
    decoder.feed(framed.data(), framed.size());

    const char* out = NULL;
    size_t out_size = 0;
    ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size))
        << "size " << size << ": " << decoder.error();
    EXPECT_EQ(size, out_size);
    expect_bytes(body, out, out_size);
  }
}

TEST_F(FrameUnitTest, RoundTripOversizedIsSplit) {
  const size_t size = FrameCodec::MAX_PAYLOAD_LENGTH * 2 + 7;
  const String body = envelope(size);
  const String framed = FrameCodec::encode(body);

  // Two full sized frames plus a remainder, each with its own header/trailer.
  ASSERT_EQ(3u, frame_count(size, FrameCodec::OVERHEAD));
  EXPECT_EQ(size + 3 * FrameCodec::OVERHEAD, framed.size());

  FrameDecoder decoder;
  decoder.feed(framed.data(), framed.size());

  const char* out = NULL;
  size_t out_size = 0;
  ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
  EXPECT_EQ(size, out_size);
  expect_bytes(body, out, out_size);
}

TEST_F(FrameUnitTest, SplitPayloadMarksEveryFrameNotSelfContained) {
  // The self contained flag means "only whole envelopes here", so it must be
  // clear on every frame of a multi frame payload, the last one included. The
  // server ends such a payload by accumulated frame size; marking the final
  // frame self contained makes it parse an envelope header out of a fragment.
  const size_t size = FrameCodec::MAX_PAYLOAD_LENGTH + 100;
  const String framed = FrameCodec::encode(envelope(size));
  ASSERT_EQ(2u, frame_count(size, FrameCodec::OVERHEAD));

  EXPECT_FALSE(frame_is_self_contained(framed, FrameCodec::UNCOMPRESSED_HEADER_SIZE, 3, 0,
                                       FRAME_COMPRESSION_NONE));
  EXPECT_FALSE(frame_is_self_contained(framed, FrameCodec::UNCOMPRESSED_HEADER_SIZE, 3, 1,
                                       FRAME_COMPRESSION_NONE));
}

TEST_F(FrameUnitTest, SingleFramePayloadIsSelfContained) {
  const String framed = FrameCodec::encode(envelope(1000));
  EXPECT_TRUE(frame_is_self_contained(framed, FrameCodec::UNCOMPRESSED_HEADER_SIZE, 3, 0,
                                      FRAME_COMPRESSION_NONE));
}

TEST_F(FrameUnitTest, RoundTripSplitAcrossFeeds) {
  const String body = payload(1000);
  const String framed = FrameCodec::encode(body);

  // Feed the frame one byte at a time; only the final feed may yield a payload.
  FrameDecoder decoder;
  for (size_t i = 0; i + 1 < framed.size(); ++i) {
    decoder.feed(framed.data() + i, 1);
    const char* out = NULL;
    size_t out_size = 0;
    ASSERT_EQ(FrameDecoder::RESULT_NEED_MORE, decoder.next(&out, &out_size)) << "at byte " << i;
  }
  decoder.feed(framed.data() + framed.size() - 1, 1);

  const char* out = NULL;
  size_t out_size = 0;
  ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
  EXPECT_EQ(1000u, out_size);
  expect_bytes(body, out, out_size);
}

TEST_F(FrameUnitTest, MultiFramePayloadResumesWhenFramesArriveSeparately) {
  // The peer may deliver one frame per read, so a payload spanning several
  // frames is reported NEED_MORE between frames and must resume rather than
  // restart when the next frame lands.
  const size_t size = FrameCodec::MAX_PAYLOAD_LENGTH * 3 + 11;
  const String body = envelope(size);
  const String framed = FrameCodec::encode(body);
  ASSERT_EQ(4u, frame_count(size, FrameCodec::OVERHEAD));

  FrameDecoder decoder;

  // Every frame boundary: expect NEED_MORE, and remember the split points.
  std::vector<size_t> frame_ends;
  {
    size_t offset = 0;
    for (size_t i = 0; i < frame_count(size, FrameCodec::OVERHEAD); ++i) {
      uint64_t packed = 0;
      for (int b = 2; b >= 0; --b) packed = (packed << 8) | static_cast<uint8_t>(framed[offset + b]);
      const size_t payload_length = static_cast<size_t>(packed & 0x1FFFF);
      offset += FrameCodec::UNCOMPRESSED_HEADER_SIZE + payload_length + FrameCodec::TRAILER_SIZE;
      frame_ends.push_back(offset);
    }
    ASSERT_EQ(framed.size(), offset);
  }

  size_t fed = 0;
  for (size_t i = 0; i + 1 < frame_ends.size(); ++i) {
    const size_t chunk = frame_ends[i] - fed;
    decoder.feed(framed.data() + fed, chunk);
    fed += chunk;

    const char* out = NULL;
    size_t out_size = 0;
    ASSERT_EQ(FrameDecoder::RESULT_NEED_MORE, decoder.next(&out, &out_size))
        << "after frame " << i << ": " << decoder.error();
  }
  decoder.feed(framed.data() + fed, framed.size() - fed);

  const char* out = NULL;
  size_t out_size = 0;
  ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
  EXPECT_EQ(size, out_size);
  expect_bytes(body, out, out_size);
}

TEST_F(FrameUnitTest, CompressedMultiFramePayloadResumesWhenFramesArriveSeparately) {
  const size_t size = FrameCodec::MAX_PAYLOAD_LENGTH * 2 + 11;
  const String body = envelope(size);
  const String framed = FrameCodec::encode(body, FRAME_COMPRESSION_LZ4);
  ASSERT_EQ(3u, frame_count(size, FrameCodec::COMPRESSED_OVERHEAD));

  FrameDecoder decoder(FRAME_COMPRESSION_LZ4);

  // Split at the first frame boundary.
  uint64_t packed = 0;
  for (int b = 4; b >= 0; --b) packed = (packed << 8) | static_cast<uint8_t>(framed[b]);
  const size_t first_frame =
      FrameCodec::COMPRESSED_HEADER_SIZE + static_cast<size_t>(packed & 0x1FFFF) + FrameCodec::TRAILER_SIZE;
  decoder.feed(framed.data(), first_frame);

  const char* out = NULL;
  size_t out_size = 0;
  ASSERT_EQ(FrameDecoder::RESULT_NEED_MORE, decoder.next(&out, &out_size)) << decoder.error();

  decoder.feed(framed.data() + first_frame, framed.size() - first_frame);
  ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
  EXPECT_EQ(size, out_size);
  expect_bytes(body, out, out_size);
}

TEST_F(FrameUnitTest, MultipleFramesInOneFeed) {
  const String first = payload(100);
  const String second = payload(200);
  const String third = payload(300);

  String stream = FrameCodec::encode(first);
  stream += FrameCodec::encode(second);
  stream += FrameCodec::encode(third);

  FrameDecoder decoder;
  decoder.feed(stream.data(), stream.size());

  const String* expected[] = { &first, &second, &third };
  for (int i = 0; i < 3; ++i) {
    const char* out = NULL;
    size_t out_size = 0;
    ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
    EXPECT_EQ(expected[i]->size(), out_size);
    expect_bytes(*expected[i], out, out_size);
  }

  const char* out = NULL;
  size_t out_size = 0;
  EXPECT_EQ(FrameDecoder::RESULT_NEED_MORE, decoder.next(&out, &out_size));
}

TEST_F(FrameUnitTest, MultiBufferPayloadMatchesContiguousCrc) {
  // A payload split across several buffers must checksum identically to the
  // same payload held in one buffer.
  const String whole = payload(300);

  BufferVec buffers;
  for (size_t i = 0; i < whole.size(); i += 37) {
    const size_t n = (whole.size() - i < 37) ? whole.size() - i : 37;
    buffers.push_back(Buffer(whole.data() + i, n));
  }

  EXPECT_EQ(compute_crc32(whole.data(), whole.size()),
            FrameCodec::payload_crc(buffers, 0, buffers.size()));

  BufferVec output;
  FrameCodec::encode(buffers, 0, buffers.size(), &output);

  String joined;
  for (size_t i = 0; i < output.size(); ++i) {
    joined.append(output[i].data(), output[i].size());
  }

  FrameDecoder decoder;
  decoder.feed(joined.data(), joined.size());
  const char* out = NULL;
  size_t out_size = 0;
  ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
  EXPECT_EQ(whole.size(), out_size);
  expect_bytes(whole, out, out_size);
}

TEST_F(FrameUnitTest, DetectsCorruptedHeader) {
  String framed = FrameCodec::encode(payload(100));
  framed[1] = static_cast<char>(framed[1] ^ 0x01);

  FrameDecoder decoder;
  decoder.feed(framed.data(), framed.size());

  const char* out = NULL;
  size_t out_size = 0;
  EXPECT_EQ(FrameDecoder::RESULT_ERROR, decoder.next(&out, &out_size));
  EXPECT_NE(std::string::npos, std::string(decoder.error()).find("Header CRC mismatch"));
}

TEST_F(FrameUnitTest, DetectsCorruptedPayload) {
  String framed = FrameCodec::encode(payload(100));
  framed[6 + 50] = static_cast<char>(framed[6 + 50] ^ 0x01);

  FrameDecoder decoder;
  decoder.feed(framed.data(), framed.size());

  const char* out = NULL;
  size_t out_size = 0;
  EXPECT_EQ(FrameDecoder::RESULT_ERROR, decoder.next(&out, &out_size));
  EXPECT_NE(std::string::npos, std::string(decoder.error()).find("Payload CRC mismatch"));
}

TEST_F(FrameUnitTest, DetectsTruncatedFrame) {
  const String framed = FrameCodec::encode(payload(100));

  FrameDecoder decoder;
  decoder.feed(framed.data(), framed.size() - 1);

  const char* out = NULL;
  size_t out_size = 0;
  EXPECT_EQ(FrameDecoder::RESULT_NEED_MORE, decoder.next(&out, &out_size));

  // Completing the frame makes it decodable.
  decoder.feed(framed.data() + framed.size() - 1, 1);
  EXPECT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size));
}

TEST_F(FrameUnitTest, CompressedReferenceFrameBytes) {
  // A small payload is below the compression threshold, so it is stored as-is
  // inside an 8 byte header: clen == payload size and ulen == 0.
  const String body = payload(50);
  const String framed = FrameCodec::encode(body, FRAME_COMPRESSION_LZ4);

  ASSERT_EQ(50u + FrameCodec::COMPRESSED_OVERHEAD, framed.size());

  // The 5 packed bytes are clen | (ulen << 17) | (1 << 34) little-endian.
  // With ulen == 0 only the self contained bit contributes to the high byte.
  const uint64_t expected_header = 50u | (static_cast<uint64_t>(1) << 34);
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(static_cast<uint8_t>((expected_header >> (8 * i)) & 0xFF),
              static_cast<uint8_t>(framed[i]))
        << "header byte " << i;
  }
  EXPECT_EQ(0x04, static_cast<uint8_t>(framed[4]));

  // The CRC24 covers the first 5 bytes only.
  const uint32_t expected_crc24 = compute_crc24(framed.data(), 5);
  EXPECT_EQ(expected_crc24, FrameCodec::decode_uint24(framed.data() + 5));

  // The trailer checksums the bytes as transmitted.
  EXPECT_EQ(compute_crc32(framed.data() + 8, 50),
            FrameCodec::decode_uint32(framed.data() + 8 + 50));
}

TEST_F(FrameUnitTest, CompressedFrameIsActuallyCompressed) {
  // A long, highly compressible payload must shrink and report a non zero
  // uncompressed length.
  const String body = payload(8192);
  const String framed = FrameCodec::encode(body, FRAME_COMPRESSION_LZ4);

  ASSERT_LT(framed.size(), body.size());

  // Recompute the packed fields the same way the decoder does.
  uint64_t packed = 0;
  for (int i = 4; i >= 0; --i) {
    packed = (packed << 8) | static_cast<uint8_t>(framed[i]);
  }
  const size_t clen = static_cast<size_t>(packed & 0x1FFFF);
  const size_t ulen = static_cast<size_t>((packed >> 17) & 0x1FFFF);

  EXPECT_EQ(8192u, ulen);
  EXPECT_LT(clen, 8192u);
  EXPECT_EQ(framed.size(), clen + FrameCodec::COMPRESSED_OVERHEAD);
  EXPECT_TRUE((packed & (static_cast<uint64_t>(1) << 34)) != 0);
}

TEST_F(FrameUnitTest, CompressedRoundTripContiguous) {
  for (size_t size = 0; size < 512; ++size) {
    const String body = payload(size);
    const String framed = FrameCodec::encode(body, FRAME_COMPRESSION_LZ4);

    FrameDecoder decoder(FRAME_COMPRESSION_LZ4);
    decoder.feed(framed.data(), framed.size());

    const char* out = NULL;
    size_t out_size = 0;
    ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size))
        << "size " << size << ": " << decoder.error();
    EXPECT_EQ(size, out_size);
    expect_bytes(body, out, out_size);
  }
}

TEST_F(FrameUnitTest, CompressedRoundTripLargePayload) {
  const String body = envelope(256 * 1024);
  const String framed = FrameCodec::encode(body, FRAME_COMPRESSION_LZ4);

  FrameDecoder decoder(FRAME_COMPRESSION_LZ4);
  decoder.feed(framed.data(), framed.size());

  const char* out = NULL;
  size_t out_size = 0;
  ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
  EXPECT_EQ(body.size(), out_size);
  expect_bytes(body, out, out_size);
}

TEST_F(FrameUnitTest, CompressedOversizedIsSplit) {
  // Chunks at the frame size limit cannot be compressed without risking an
  // overflow, so they are split and stored as-is.
  const size_t size = FrameCodec::MAX_PAYLOAD_LENGTH * 2 + 7;
  const String body = envelope(size);
  const String framed = FrameCodec::encode(body, FRAME_COMPRESSION_LZ4);

  ASSERT_EQ(3u, frame_count(size, FrameCodec::COMPRESSED_OVERHEAD));
  EXPECT_EQ(size + 3 * FrameCodec::COMPRESSED_OVERHEAD, framed.size());

  FrameDecoder decoder(FRAME_COMPRESSION_LZ4);
  decoder.feed(framed.data(), framed.size());

  const char* out = NULL;
  size_t out_size = 0;
  ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
  EXPECT_EQ(size, out_size);
  expect_bytes(body, out, out_size);
}

TEST_F(FrameUnitTest, CompressedSplitPayloadMarksEveryFrameNotSelfContained) {
  const size_t size = FrameCodec::MAX_PAYLOAD_LENGTH + 100;
  const String framed = FrameCodec::encode(envelope(size), FRAME_COMPRESSION_LZ4);
  ASSERT_EQ(2u, frame_count(size, FrameCodec::COMPRESSED_OVERHEAD));

  EXPECT_FALSE(frame_is_self_contained(framed, FrameCodec::COMPRESSED_HEADER_SIZE, 5, 0,
                                       FRAME_COMPRESSION_LZ4));
  EXPECT_FALSE(frame_is_self_contained(framed, FrameCodec::COMPRESSED_HEADER_SIZE, 5, 1,
                                       FRAME_COMPRESSION_LZ4));
}

TEST_F(FrameUnitTest, CompressedRoundTripSplitAcrossFeeds) {
  const String body = payload(4096);
  const String framed = FrameCodec::encode(body, FRAME_COMPRESSION_LZ4);

  FrameDecoder decoder(FRAME_COMPRESSION_LZ4);
  for (size_t i = 0; i + 1 < framed.size(); ++i) {
    decoder.feed(framed.data() + i, 1);
    const char* out = NULL;
    size_t out_size = 0;
    ASSERT_EQ(FrameDecoder::RESULT_NEED_MORE, decoder.next(&out, &out_size)) << "at byte " << i;
  }
  decoder.feed(framed.data() + framed.size() - 1, 1);

  const char* out = NULL;
  size_t out_size = 0;
  ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
  EXPECT_EQ(body.size(), out_size);
  expect_bytes(body, out, out_size);
}

TEST_F(FrameUnitTest, CompressedMultipleFramesInOneFeed) {
  const String first = payload(4096);
  const String second = payload(64);
  const String third = payload(8192);

  String stream = FrameCodec::encode(first, FRAME_COMPRESSION_LZ4);
  stream += FrameCodec::encode(second, FRAME_COMPRESSION_LZ4);
  stream += FrameCodec::encode(third, FRAME_COMPRESSION_LZ4);

  FrameDecoder decoder(FRAME_COMPRESSION_LZ4);
  decoder.feed(stream.data(), stream.size());

  const String* expected[] = { &first, &second, &third };
  for (int i = 0; i < 3; ++i) {
    const char* out = NULL;
    size_t out_size = 0;
    ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
    EXPECT_EQ(expected[i]->size(), out_size);
    expect_bytes(*expected[i], out, out_size);
  }
}

TEST_F(FrameUnitTest, CompressedDetectsCorruptedHeader) {
  String framed = FrameCodec::encode(payload(4096), FRAME_COMPRESSION_LZ4);
  framed[1] = static_cast<char>(framed[1] ^ 0x01);

  FrameDecoder decoder(FRAME_COMPRESSION_LZ4);
  decoder.feed(framed.data(), framed.size());

  const char* out = NULL;
  size_t out_size = 0;
  EXPECT_EQ(FrameDecoder::RESULT_ERROR, decoder.next(&out, &out_size));
  EXPECT_NE(std::string::npos, std::string(decoder.error()).find("Header CRC mismatch"));
}

TEST_F(FrameUnitTest, CompressedDetectsCorruptedPayload) {
  String framed = FrameCodec::encode(payload(4096), FRAME_COMPRESSION_LZ4);
  framed[FrameCodec::COMPRESSED_HEADER_SIZE + 10] =
      static_cast<char>(framed[FrameCodec::COMPRESSED_HEADER_SIZE + 10] ^ 0x01);

  FrameDecoder decoder(FRAME_COMPRESSION_LZ4);
  decoder.feed(framed.data(), framed.size());

  const char* out = NULL;
  size_t out_size = 0;
  EXPECT_EQ(FrameDecoder::RESULT_ERROR, decoder.next(&out, &out_size));
  EXPECT_NE(std::string::npos, std::string(decoder.error()).find("Payload CRC mismatch"));
}

TEST_F(FrameUnitTest, CompressedDetectsInvalidLz4Stream) {
  // Build a frame whose payload passes the CRC32 check but is not a valid LZ4
  // block. The declared uncompressed length is non zero so the decoder must try
  // to decompress and fail.
  const size_t uncompressed_size = 256;
  const size_t compressed_size = 64;
  const char garbage = 0x7F;

  String body(compressed_size, garbage);
  String framed;
  framed.resize(FrameCodec::COMPRESSED_HEADER_SIZE);
  FrameCodec::encode_compressed_header(&framed[0], compressed_size, uncompressed_size, true);
  framed += body;
  Buffer trailer(FrameCodec::TRAILER_SIZE);
  FrameCodec::encode_trailer(trailer.data(), compute_crc32(body.data(), body.size()));
  framed.append(trailer.data(), trailer.size());

  FrameDecoder decoder(FRAME_COMPRESSION_LZ4);
  decoder.feed(framed.data(), framed.size());

  const char* out = NULL;
  size_t out_size = 0;
  EXPECT_EQ(FrameDecoder::RESULT_ERROR, decoder.next(&out, &out_size));
  EXPECT_NE(std::string::npos, std::string(decoder.error()).find("Failed to decompress"));
}

TEST_F(FrameUnitTest, HeaderSizeIsFixedByNegotiation) {
  // The two header layouts cannot be told apart from the bytes alone, so an
  // uncompressed decoder handed a compressed stream must not silently accept
  // it as garbage without noticing the CRC24 covers the wrong number of bytes.
  const String framed = FrameCodec::encode(payload(4096), FRAME_COMPRESSION_LZ4);

  FrameDecoder decoder(FRAME_COMPRESSION_NONE);
  decoder.feed(framed.data(), framed.size());

  const char* out = NULL;
  size_t out_size = 0;
  EXPECT_EQ(FrameDecoder::RESULT_ERROR, decoder.next(&out, &out_size));
}

TEST_F(FrameUnitTest, CompressionAvailabilityMatchesBuild) {
  EXPECT_TRUE(datastax::internal::core::frame_compression_available(FRAME_COMPRESSION_NONE));
#ifdef HAVE_LZ4
  EXPECT_TRUE(datastax::internal::core::frame_compression_available(FRAME_COMPRESSION_LZ4));
#else
  EXPECT_FALSE(datastax::internal::core::frame_compression_available(FRAME_COMPRESSION_LZ4));
#endif
}

TEST_F(FrameUnitTest, OverheadReflectsHeaderSize) {
  EXPECT_EQ(FrameCodec::OVERHEAD, FrameCodec::overhead(FRAME_COMPRESSION_NONE));
  EXPECT_EQ(FrameCodec::COMPRESSED_OVERHEAD, FrameCodec::overhead(FRAME_COMPRESSION_LZ4));
  EXPECT_EQ(FrameCodec::COMPRESSED_OVERHEAD,
            FrameCodec::overhead(100, FRAME_COMPRESSION_LZ4));
  // An oversized payload needs one header and trailer per frame.
  EXPECT_EQ(2 * FrameCodec::COMPRESSED_OVERHEAD,
            FrameCodec::overhead(FrameCodec::MAX_PAYLOAD_LENGTH + 1, FRAME_COMPRESSION_LZ4));
}
/**
 * The driver accepts keyspaces as CQL identifiers, so a case sensitive keyspace
 * reaches us quoted ("CaseSensitive"). Protocol v5 carries the keyspace name in
 * a dedicated field where the quotes must be removed.
 */
TEST_F(FrameUnitTest, UnescapeId) {
  using datastax::internal::unescape_id;

  EXPECT_EQ("casesensitive", unescape_id("casesensitive"));
  EXPECT_EQ("CaseSensitive", unescape_id("\"CaseSensitive\""));
  EXPECT_EQ("", unescape_id(""));
  EXPECT_EQ("", unescape_id("\"\""));
  EXPECT_EQ("a\"b", unescape_id("\"a\"\"b\""));
  // Not a quoted identifier: returned as-is.
  EXPECT_EQ("\"unterminated", unescape_id("\"unterminated"));
  EXPECT_EQ("\"mismatched'", unescape_id("\"mismatched'"));
}

/**
 * A duration is three signed vints (zig-zag encoded) for months, days and
 * nanoseconds. Reference values produced with the DataStax Python driver's
 * duration implementation.
 */
TEST_F(FrameUnitTest, DecodesDuration) {
  using datastax::internal::core::Decoder;

  // 1 month, 2 days, 3 nanoseconds -> zig-zag 2, 4, 6
  const char encoded[] = { '\x02', '\x04', '\x06' };
  Decoder decoder(encoded, sizeof(encoded), ProtocolVersion(CASS_PROTOCOL_VERSION_V5));

  int32_t months = -1;
  int32_t days = -1;
  int64_t nanos = -1;
  ASSERT_TRUE(decoder.as_duration(&months, &days, &nanos));
  EXPECT_EQ(1, months);
  EXPECT_EQ(2, days);
  EXPECT_EQ(3, nanos);

  // -1 month, 0 days, 0 nanoseconds -> zig-zag 1, 0, 0
  const char negative[] = { '\x01', '\x00', '\x00' };
  Decoder negative_decoder(negative, sizeof(negative), ProtocolVersion(CASS_PROTOCOL_VERSION_V5));
  months = 0;
  days = 0;
  nanos = 0;
  ASSERT_TRUE(negative_decoder.as_duration(&months, &days, &nanos));
  EXPECT_EQ(-1, months);
  EXPECT_EQ(0, days);
  EXPECT_EQ(0, nanos);
}

namespace {

using datastax::internal::core::BatchRequest;
using datastax::internal::core::QueryRequest;
using datastax::internal::core::Request;
using datastax::internal::core::ResponseMessage;
using datastax::internal::core::SimpleRequestCallback;

/**
 * The batch encoder only reads settings from the request, so a callback that
 * swallows the response is enough to drive it.
 */
class NoOpRequestCallback : public SimpleRequestCallback {
public:
  explicit NoOpRequestCallback(const Request::ConstPtr& request)
      : SimpleRequestCallback(request) {}

protected:
  virtual void on_internal_set(ResponseMessage* response) {}
  virtual void on_internal_error(CassError code, const String& message) {}
  virtual void on_internal_timeout() {}
};

/**
 * Encodes a batch and hands back the trailing <consistency><flags>[...]
 * parameter buffer, which is the last buffer the encoder appends.
 */
String encode_batch_params(ProtocolVersion version) {
  QueryRequest::Ptr statement(new QueryRequest("INSERT INTO t (k) VALUES (1)", 0));

  // SharedRefPtr takes ownership, so the request must be heap allocated.
  BatchRequest* batch = new BatchRequest(CASS_BATCH_TYPE_LOGGED);
  batch->add_statement(statement.get());
  batch->set_consistency(CASS_CONSISTENCY_ONE);
  batch->set_serial_consistency(CASS_CONSISTENCY_LOCAL_SERIAL);
  batch->set_timestamp(0x0102030405060708LL);
  batch->set_now_in_seconds(1234);
  // Quoted on the way in, unescaped on the wire.
  batch->set_keyspace("\"CaseSensitive\"");

  Request::ConstPtr request(batch);
  NoOpRequestCallback callback(request);

  BufferVec bufs;
  // BatchRequest::encode() is private; dispatch through the base interface.
  const Request* base = request.get();
  EXPECT_GT(base->encode(version, &callback, &bufs), 0);

  if (bufs.empty()) {
    return String();
  }
  const Buffer& params = bufs.back();
  return String(params.data(), params.size());
}

} // namespace

/**
 * Protocol v5 widened <flags> to [int] and requires the parameter block to be
 * ordered <serial_consistency><timestamp><keyspace><now_in_seconds>. Encoding
 * <now_in_seconds> ahead of <keyspace> desynchronizes the reader, so assert the
 * exact bytes. CQL integers are big endian.
 */
TEST_F(FrameUnitTest, BatchV5QueryParamOrder) {
  String params = encode_batch_params(ProtocolVersion(CASS_PROTOCOL_VERSION_V5));
  const char* p = params.data();

  // consistency[2] flags[4] serial[2] timestamp[8] keyspace[2+13] now[4]
  ASSERT_EQ(2u + 4u + 2u + 8u + 2u + 13u + 4u, params.size());

  // <consistency> [short] = ONE
  EXPECT_EQ(0x00, p[0]);
  EXPECT_EQ(0x01, p[1]);

  // <flags> [int]: serial | timestamp | keyspace | now_in_seconds
  EXPECT_EQ(0x00, p[2]);
  EXPECT_EQ(0x00, p[3]);
  EXPECT_EQ(0x01, p[4]);
  EXPECT_EQ(0xb0, static_cast<unsigned char>(p[5]));

  // <serial_consistency> [short] = LOCAL_SERIAL (0x0009)
  EXPECT_EQ(0x00, p[6]);
  EXPECT_EQ(0x09, p[7]);

  // <timestamp> [long]
  for (int i = 0; i < 8; ++i) {
    EXPECT_EQ(static_cast<char>(0x01 + i), p[8 + i]);
  }

  // <keyspace> [string]: 13 characters, quotes stripped by unescape_id()
  EXPECT_EQ(0x00, p[16]);
  EXPECT_EQ(0x0d, p[17]);
  EXPECT_EQ("CaseSensitive", String(p + 18, 13));

  // <now_in_seconds> [int] = 1234 -- must come last.
  EXPECT_EQ(0x00, p[31]);
  EXPECT_EQ(0x00, p[32]);
  EXPECT_EQ(0x04, p[33]);
  EXPECT_EQ(0xd2, static_cast<unsigned char>(p[34]));
}

/**
 * DSE v2 predates the With_now_in_seconds flag but still uses the widened
 * four byte <flags> introduced by v5, so the field width must not be tied to
 * now_in_seconds support.
 */
TEST_F(FrameUnitTest, BatchV4KeepsNarrowFlags) {
  const String v4 = encode_batch_params(ProtocolVersion(CASS_PROTOCOL_VERSION_V4));

  // v4 keeps <flags> as a single byte and never carries a keyspace or
  // now_in_seconds, so only consistency/serial/timestamp are present.
  ASSERT_EQ(2u + 1u + 2u + 8u, v4.size());
  EXPECT_EQ(0x30, static_cast<unsigned char>(v4.data()[2])); // serial | timestamp
}

/**
 * DSE v2 predates the With_now_in_seconds flag but still uses the widened four
 * byte <flags>, so the field width must follow query_flags_size() rather than
 * now_in_seconds support. Encoding a single byte here would desynchronize every
 * following field.
 */
TEST_F(FrameUnitTest, BatchDseV2KeepsWideFlags) {
  const String dse = encode_batch_params(ProtocolVersion(CASS_PROTOCOL_VERSION_DSEV2));

  // DSE v2 supports the keyspace field but not now_in_seconds, so it carries
  // every field except the trailing [int].
  // consistency[2] flags[4] serial[2] timestamp[8] keyspace[2+13]
  ASSERT_EQ(2u + 4u + 2u + 8u + 2u + 13u, dse.size());
  const char* p = dse.data();

  // <flags> [int] = serial | timestamp | keyspace (no now_in_seconds)
  EXPECT_EQ(0x00, p[2]);
  EXPECT_EQ(0x00, p[3]);
  EXPECT_EQ(0x00, p[4]);
  EXPECT_EQ(0xb0, static_cast<unsigned char>(p[5]));

  // <serial_consistency> [short] = LOCAL_SERIAL
  EXPECT_EQ(0x00, p[6]);
  EXPECT_EQ(0x09, p[7]);

  // <keyspace> [string], still unescaped
  EXPECT_EQ("CaseSensitive", String(p + 18, 13));
}
