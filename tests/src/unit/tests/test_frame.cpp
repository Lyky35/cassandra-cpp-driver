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

#include "buffer.hpp"
#include "crc.hpp"
#include "decoder.hpp"
#include "frame.hpp"
#include "protocol.hpp"
#include "utils.hpp"

using datastax::internal::core::Buffer;
using datastax::internal::core::BufferVec;
using datastax::internal::core::FrameCodec;
using datastax::internal::core::FrameDecoder;
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
  const String body = payload(size);
  const String framed = FrameCodec::encode(body);

  // Two full sized frames plus a remainder, each with its own header/trailer.
  EXPECT_EQ(size + 3 * FrameCodec::OVERHEAD, framed.size());

  FrameDecoder decoder;
  decoder.feed(framed.data(), framed.size());

  const char* out = NULL;
  size_t out_size = 0;
  ASSERT_EQ(FrameDecoder::RESULT_OK, decoder.next(&out, &out_size)) << decoder.error();
  EXPECT_EQ(size, out_size);
  expect_bytes(body, out, out_size);
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
