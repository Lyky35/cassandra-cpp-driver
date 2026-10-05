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

#include "frame.hpp"

#include "crc.hpp"
#include "driver_config.hpp"
#include "serialization.hpp"

#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#include <string.h>

using namespace datastax;
using namespace datastax::internal::core;

namespace datastax { namespace internal { namespace core {

namespace {

// Bit 17 of the packed header integer is the "self contained" flag; bits 0-16
// hold the payload length. The remaining 6 bits are padding.
const uint32_t SELF_CONTAINED_BIT = 17;
const uint32_t PAYLOAD_LENGTH_MASK = 0x1FFFF;

// Bit layout of the 8 byte compressed header. The first 5 bytes hold a 40 bit
// little-endian value: bits 0-16 are the compressed length, bits 17-33 the
// uncompressed length, bit 34 the "self contained" flag, and bits 35-39 are
// padding. The CRC24 in the last 3 bytes covers the first 5 bytes only. The
// packed value needs 40 bits, hence uint64_t rather than uint32_t.
const uint32_t COMPRESSED_UNCOMPRESSED_LENGTH_SHIFT = 17;
const uint64_t COMPRESSED_SELF_CONTAINED_BIT = 34;
const int COMPRESSED_HEADER_CRC_OFFSET = 5;

// Payloads below this size are sent uncompressed even when LZ4 is negotiated.
// Framing overhead dominates at small sizes, and compressing tiny buffers costs
// CPU without saving meaningful bandwidth.
const size_t MIN_COMPRESSION_SIZE = 128;

} // namespace

// Out of class definitions for the in class initialized static constants.
// These are required as soon as any of them is odr-used, for example when a
// test binds one to a reference.
const size_t FrameCodec::MAX_PAYLOAD_LENGTH;
const size_t FrameCodec::UNCOMPRESSED_HEADER_SIZE;
const size_t FrameCodec::COMPRESSED_HEADER_SIZE;
const size_t FrameCodec::TRAILER_SIZE;
const size_t FrameCodec::OVERHEAD;
const size_t FrameCodec::COMPRESSED_OVERHEAD;
const size_t FrameCodec::MIN_HEADER_SIZE;
const size_t FrameDecoder::MAX_PAYLOAD_SIZE;

bool frame_compression_available(FrameCompression compression) {
  if (compression == FRAME_COMPRESSION_NONE) return true;
#ifdef HAVE_LZ4
  return true;
#else
  return false;
#endif
}

size_t FrameCodec::overhead(size_t payload_size, FrameCompression compression) {
  if (payload_size == 0) return overhead(compression);
  const size_t frames = (payload_size + MAX_PAYLOAD_LENGTH - 1) / MAX_PAYLOAD_LENGTH;
  return frames * overhead(compression);
}

size_t FrameCodec::compress_bound(size_t size) {
#ifdef HAVE_LZ4
  return static_cast<size_t>(LZ4_compressBound(static_cast<int>(size)));
#else
  // Worst case is the input plus a small margin; never claimed to be exact.
  return size + (size / 255) + 16;
#endif
}

void FrameCodec::encode_uint24(char* output, uint32_t value) {
  output[0] = static_cast<char>(value & 0xFF);
  output[1] = static_cast<char>((value >> 8) & 0xFF);
  output[2] = static_cast<char>((value >> 16) & 0xFF);
}

uint32_t FrameCodec::decode_uint24(const char* input) {
  return static_cast<uint32_t>(static_cast<uint8_t>(input[0])) |
         (static_cast<uint32_t>(static_cast<uint8_t>(input[1])) << 8) |
         (static_cast<uint32_t>(static_cast<uint8_t>(input[2])) << 16);
}

void FrameCodec::encode_uint32(char* output, uint32_t value) {
  output[0] = static_cast<char>(value & 0xFF);
  output[1] = static_cast<char>((value >> 8) & 0xFF);
  output[2] = static_cast<char>((value >> 16) & 0xFF);
  output[3] = static_cast<char>((value >> 24) & 0xFF);
}

uint32_t FrameCodec::decode_uint32(const char* input) {
  return static_cast<uint32_t>(static_cast<uint8_t>(input[0])) |
         (static_cast<uint32_t>(static_cast<uint8_t>(input[1])) << 8) |
         (static_cast<uint32_t>(static_cast<uint8_t>(input[2])) << 16) |
         (static_cast<uint32_t>(static_cast<uint8_t>(input[3])) << 24);
}

void FrameCodec::encode_header(char* output, size_t payload_size) {
  encode_header(output, payload_size, true);
}

void FrameCodec::encode_header(char* output, size_t payload_size, bool self_contained) {
  assert(payload_size <= MAX_PAYLOAD_LENGTH && "Frame payload is too large");
  const uint32_t header = static_cast<uint32_t>(payload_size) |
                          (self_contained ? (1u << SELF_CONTAINED_BIT) : 0u);
  encode_uint24(output, header);
  encode_uint24(output + 3, compute_crc24(output, 3));
}

void FrameCodec::encode_compressed_header(char* output, size_t compressed_size,
                                          size_t uncompressed_size, bool self_contained) {
  assert(compressed_size <= MAX_PAYLOAD_LENGTH && "Frame payload is too large");
  assert(uncompressed_size <= MAX_PAYLOAD_LENGTH && "Frame payload is too large");
  // Only the low 17 bits of each length are transmitted.
  uint64_t header = static_cast<uint64_t>(compressed_size & PAYLOAD_LENGTH_MASK);
  header |= static_cast<uint64_t>(uncompressed_size & PAYLOAD_LENGTH_MASK)
            << COMPRESSED_UNCOMPRESSED_LENGTH_SHIFT;
  if (self_contained) {
    header |= (static_cast<uint64_t>(1) << COMPRESSED_SELF_CONTAINED_BIT);
  }
  // The packed fields occupy 5 bytes; write them little-endian.
  for (int i = 0; i < COMPRESSED_HEADER_CRC_OFFSET; ++i) {
    output[i] = static_cast<char>((header >> (8 * i)) & 0xFF);
  }
  encode_uint24(output + COMPRESSED_HEADER_CRC_OFFSET,
                compute_crc24(output, COMPRESSED_HEADER_CRC_OFFSET));
}

int32_t FrameCodec::compress(const char* payload, size_t size, char* output) {
#ifdef HAVE_LZ4
  if (size == 0) return -1;
  const int compressed = LZ4_compress_default(payload, output, static_cast<int>(size),
                                              static_cast<int>(compress_bound(size)));
  if (compressed <= 0) return -1;
  return compressed;
#else
  (void)payload;
  (void)size;
  (void)output;
  return -1;
#endif
}

int32_t FrameCodec::compress(const BufferVec& payload, size_t start, size_t end,
                             char* output) {
  size_t total = 0;
  for (size_t i = start; i < end; ++i) {
    total += payload[i].size();
  }
  if (total == 0 || total > MAX_PAYLOAD_LENGTH) return -1;

  // LZ4 needs to see the payload as one piece, so the buffers are copied into a
  // contiguous staging block first.
  Buffer contiguous(total);
  char* out = contiguous.data();
  size_t written = 0;
  for (size_t i = start; i < end; ++i) {
    const Buffer& buf = payload[i];
    if (buf.size() > 0) {
      memcpy(out + written, buf.data(), buf.size());
      written += buf.size();
    }
  }
  return compress(contiguous.data(), written, output);
}

int32_t FrameCodec::decompress(const char* payload, size_t size,
                               size_t uncompressed_size, char* output) {
#ifdef HAVE_LZ4
  if (uncompressed_size == 0) return -1;
  const int decompressed = LZ4_decompress_safe(payload, output, static_cast<int>(size),
                                               static_cast<int>(uncompressed_size));
  if (decompressed < 0 || static_cast<size_t>(decompressed) != uncompressed_size) {
    return -1;
  }
  return decompressed;
#else
  (void)payload;
  (void)size;
  (void)uncompressed_size;
  (void)output;
  return -1;
#endif
}

void FrameCodec::encode_trailer(char* output, uint32_t crc) { encode_uint32(output, crc); }

uint32_t FrameCodec::payload_crc(const char* data, size_t size) {
  return compute_crc32(data, size);
}

uint32_t FrameCodec::payload_crc(const BufferVec& payload, size_t start, size_t end) {
  uint32_t crc = compute_crc32_init();
  for (size_t i = start; i < end; ++i) {
    const Buffer& buf = payload[i];
    if (buf.size() > 0) {
      crc = compute_crc32_update(crc, buf.data(), buf.size());
    }
  }
  return crc;
}

int32_t FrameCodec::encode(const BufferVec& payload, BufferVec* output,
                           FrameCompression compression) {
  return encode(payload, 0, payload.size(), output, compression);
}

int32_t FrameCodec::encode(const BufferVec& payload, size_t start, size_t end,
                           BufferVec* output, FrameCompression compression) {
  output->clear();

  size_t total = 0;
  for (size_t i = start; i < end; ++i) {
    total += payload[i].size();
  }

  // A compressed connection always uses the 8 byte header, even for frames
  // whose payload is stored uncompressed, because the header size is fixed for
  // the life of the connection.

  if (total <= MAX_PAYLOAD_LENGTH) {
    // Common case: a single self contained frame.
    if (compression == FRAME_COMPRESSION_NONE) {
      // The payload buffers are referenced directly so no copy is made.
      Buffer header(UNCOMPRESSED_HEADER_SIZE);
      encode_header(header.data(), total, true);
      output->push_back(header);

      for (size_t i = start; i < end; ++i) {
        if (payload[i].size() > 0) {
          output->push_back(payload[i]);
        }
      }

      Buffer trailer(TRAILER_SIZE);
      encode_trailer(trailer.data(), payload_crc(payload, start, end));
      output->push_back(trailer);

      return static_cast<int32_t>(total + OVERHEAD);
    }

    // Compressed connection: try to compress, but fall back to sending the
    // payload as-is when compression fails or would not actually help.
    Buffer compressed(compress_bound(total));
    const int32_t compressed_size =
        total >= MIN_COMPRESSION_SIZE ? compress(payload, start, end, compressed.data()) : -1;
    if (compressed_size > 0 && static_cast<size_t>(compressed_size) < total) {
      Buffer header(COMPRESSED_HEADER_SIZE);
      encode_compressed_header(header.data(), static_cast<size_t>(compressed_size), total, true);
      output->push_back(header);
      output->push_back(Buffer(compressed.data(), static_cast<size_t>(compressed_size)));

      Buffer trailer(TRAILER_SIZE);
      encode_trailer(trailer.data(),
                     payload_crc(compressed.data(), static_cast<size_t>(compressed_size)));
      output->push_back(trailer);

      return static_cast<int32_t>(static_cast<size_t>(compressed_size) + COMPRESSED_OVERHEAD);
    }

    // Uncompressed payload on a compressed connection: the on-wire length is
    // the payload size and an uncompressed length of zero says "do not
    // decompress".
    Buffer header(COMPRESSED_HEADER_SIZE);
    encode_compressed_header(header.data(), total, 0, true);
    output->push_back(header);

    for (size_t i = start; i < end; ++i) {
      if (payload[i].size() > 0) {
        output->push_back(payload[i]);
      }
    }

    Buffer trailer(TRAILER_SIZE);
    encode_trailer(trailer.data(), payload_crc(payload, start, end));
    output->push_back(trailer);

    return static_cast<int32_t>(total + COMPRESSED_OVERHEAD);
  }

  // Rare case: the payload is too large for one frame and has to be split. The
  // chunks are copied because they cannot be expressed as whole buffers.
  size_t copied = 0;
  // Cursor into the payload: buffer `index` and the offset already consumed
  // from it. This has to persist across chunks, otherwise every chunk would
  // restart at the beginning of the payload.
  size_t index = start;
  size_t within = 0;

  while (copied < total) {
    const size_t chunk_size = (total - copied < MAX_PAYLOAD_LENGTH) ? (total - copied)
                                                                   : MAX_PAYLOAD_LENGTH;
    // Every frame of a multi frame payload, including the last, is marked as
    // not self contained. The flag means "this frame carries only whole
    // envelopes", not "this is the final frame": the server ends a multi frame
    // message by accumulated frame size, and a self contained flag on the last
    // frame makes it try to parse an envelope header out of a fragment.
    const bool self_contained = false;

    Buffer chunk(chunk_size);
    char* out = chunk.data();
    size_t written = 0;
    while (written < chunk_size) {
      while (index < end && payload[index].size() == 0) {
        ++index;
      }
      if (index >= end) {
        break; // Should not happen: chunk_size is bounded by the total size.
      }
      const Buffer& buf = payload[index];
      const size_t available = buf.size() - within;
      const size_t n = (available < chunk_size - written) ? available : chunk_size - written;
      memcpy(out + written, buf.data() + within, n);
      written += n;
      within += n;
      if (within == buf.size()) {
        ++index;
        within = 0;
      }
    }

    if (compression == FRAME_COMPRESSION_NONE) {
      Buffer header(UNCOMPRESSED_HEADER_SIZE);
      encode_header(header.data(), chunk_size, self_contained);
      output->push_back(header);
      output->push_back(chunk);

      Buffer trailer(TRAILER_SIZE);
      encode_trailer(trailer.data(), compute_crc32(chunk.data(), chunk.size()));
      output->push_back(trailer);
    } else {
      // Split chunks are sent uncompressed: each chunk is already at the frame
      // size limit, so compressing it could push it over MAX_PAYLOAD_LENGTH.
      Buffer header(COMPRESSED_HEADER_SIZE);
      encode_compressed_header(header.data(), chunk_size, 0, self_contained);
      output->push_back(header);
      output->push_back(chunk);

      Buffer trailer(TRAILER_SIZE);
      encode_trailer(trailer.data(), compute_crc32(chunk.data(), chunk.size()));
      output->push_back(trailer);
    }

    copied += chunk_size;
  }

  return static_cast<int32_t>(total + overhead(total, compression));
}

int32_t FrameCodec::encode(const char* payload, size_t size, BufferVec* output,
                           FrameCompression compression) {
  Buffer buf(payload, size);
  BufferVec vec;
  vec.push_back(buf);
  return encode(vec, output, compression);
}

String FrameCodec::encode(const String& payload, FrameCompression compression) {
  BufferVec frames;
  encode(payload.data(), payload.size(), &frames, compression);

  String result;
  size_t size = 0;
  for (size_t i = 0; i < frames.size(); ++i) {
    size += frames[i].size();
  }
  result.reserve(size);
  for (size_t i = 0; i < frames.size(); ++i) {
    result.append(frames[i].data(), frames[i].size());
  }
  return result;
}

FrameDecoder::FrameDecoder(FrameCompression compression)
    : compression_(compression)
    , accumulation_offset_(0)
    , payload_size_(0) {}

void FrameDecoder::reset() {
  accumulation_.clear();
  accumulation_offset_ = 0;
  payload_.clear();
  payload_size_ = 0;
  decompressed_.clear();
  error_.clear();
}

void FrameDecoder::feed(const char* data, size_t size) {
  // Reclaim the already parsed prefix before growing.
  if (accumulation_offset_ > 0) {
    if (accumulation_offset_ == accumulation_.size()) {
      accumulation_.clear();
      accumulation_offset_ = 0;
    } else if (accumulation_offset_ >= 64 * 1024) {
      accumulation_.erase(accumulation_.begin(), accumulation_.begin() + accumulation_offset_);
      accumulation_offset_ = 0;
    }
  }

  if (size == 0) return;

  const size_t old_size = accumulation_.size();
  accumulation_.resize(old_size + size);
  if (size > 0) {
    memcpy(&accumulation_[old_size], data, size);
  }
}

FrameDecoder::Result FrameDecoder::fail(const char* message) {
  error_ = message;
  return RESULT_ERROR;
}

FrameDecoder::Result FrameDecoder::fail_crc(const char* what, uint32_t expected, uint32_t actual) {
  OStringStream ss;
  ss << what << " (expected 0x" << std::hex << expected << ", calculated 0x" << actual << ")";
  error_ = ss.str();
  return RESULT_ERROR;
}

size_t FrameDecoder::declared_payload_size() const {
  if (payload_.size() < CASS_HEADER_SIZE_V3) return 0;
  int32_t body_size = 0;
  decode_int32(&payload_[CASS_HEADER_SIZE_V3 - 4], body_size);
  // A negative body length is corrupt; treat it as "not yet decodable" so the
  // caller keeps buffering rather than trusting it.
  if (body_size < 0) return 0;
  const size_t total = CASS_HEADER_SIZE_V3 + static_cast<size_t>(body_size);
  return total > MAX_PAYLOAD_SIZE ? 0 : total;
}

bool FrameDecoder::payload_complete() const {
  const size_t total = declared_payload_size();
  return total != 0 && payload_.size() >= total;
}

FrameDecoder::Result FrameDecoder::next(const char** payload, size_t* size) {
  const char* base;
  size_t available;
  size_t offset;

  // Whatever is still in payload_ belongs to a multi frame payload whose later
  // frames have not arrived yet, so it is resumed rather than discarded: the
  // peer may pause between frames, and dropping those bytes here would strand
  // the payload until it hit the reassembly limit. A completed payload is handed
  // out and reset before returning, so an empty payload_ means a fresh start.
  for (;;) {
    base = accumulation_.empty() ? NULL : &accumulation_[0];
    available = accumulation_.size() - accumulation_offset_;
    offset = accumulation_offset_;

    if (available < FrameCodec::MIN_HEADER_SIZE) {
      return RESULT_NEED_MORE;
    }

    // The header size is fixed by negotiation: there is no bit that
    // distinguishes the two layouts, so it cannot be sniffed per frame.
    const bool compressed = compression_ != FRAME_COMPRESSION_NONE;
    const size_t header_bytes = FrameCodec::header_size(compression_);

    if (available < header_bytes) {
      return RESULT_NEED_MORE;
    }

    bool self_contained;
    size_t payload_length; // length of the bytes on the wire
    size_t plain_length;   // length after decompression; 0 means stored as-is
    uint32_t expected_header_crc;
    uint32_t actual_header_crc;

    if (compressed) {
      // 5 bytes of packed fields then a 3 byte CRC24 covering those 5 bytes.
      // The fields need 40 bits, hence uint64_t.
      uint64_t header = 0;
      for (int i = COMPRESSED_HEADER_CRC_OFFSET - 1; i >= 0; --i) {
        header = (header << 8) | static_cast<uint8_t>(base[offset + i]);
      }
      payload_length = static_cast<size_t>(header & PAYLOAD_LENGTH_MASK);
      plain_length =
          static_cast<size_t>((header >> COMPRESSED_UNCOMPRESSED_LENGTH_SHIFT) & PAYLOAD_LENGTH_MASK);
      self_contained = (header & (static_cast<uint64_t>(1) << COMPRESSED_SELF_CONTAINED_BIT)) != 0;
      expected_header_crc = FrameCodec::decode_uint24(base + offset + COMPRESSED_HEADER_CRC_OFFSET);
      actual_header_crc = compute_crc24(base + offset, COMPRESSED_HEADER_CRC_OFFSET);
    } else {
      const uint32_t header = FrameCodec::decode_uint24(base + offset);
      payload_length = header & PAYLOAD_LENGTH_MASK;
      plain_length = payload_length;
      self_contained = (header & (1u << SELF_CONTAINED_BIT)) != 0;
      expected_header_crc = FrameCodec::decode_uint24(base + offset + 3);
      actual_header_crc = compute_crc24(base + offset, 3);
    }

    if (expected_header_crc != actual_header_crc) {
      return fail_crc("Header CRC mismatch", expected_header_crc, actual_header_crc);
    }

    // A non zero uncompressed length must describe a payload that can actually
    // be produced; otherwise the peer is asking us to allocate an arbitrary
    // amount of memory.
    if (compressed && plain_length > MAX_PAYLOAD_SIZE) {
      return fail("Frame payload exceeds the maximum reassembled size");
    }

    const size_t frame_size = header_bytes + payload_length + FrameCodec::TRAILER_SIZE;
    if (available < frame_size) {
      return RESULT_NEED_MORE;
    }

    const char* frame_payload = base + offset + header_bytes;
    // The trailer covers the bytes as transmitted, so it is the CRC32 of the
    // compressed payload when the frame is compressed.
    const uint32_t expected_payload_crc =
        FrameCodec::decode_uint32(frame_payload + payload_length);
    const uint32_t actual_payload_crc = compute_crc32(frame_payload, payload_length);
    if (expected_payload_crc != actual_payload_crc) {
      return fail_crc("Payload CRC mismatch", expected_payload_crc, actual_payload_crc);
    }

    const bool needs_decompression = compressed && plain_length > 0;
    if (needs_decompression) {
      decompressed_.resize(plain_length);
      if (FrameCodec::decompress(frame_payload, payload_length, plain_length,
                                 &decompressed_[0]) < 0) {
        decompressed_.clear();
        return fail("Failed to decompress frame payload");
      }
    }

    // Append this frame's bytes to the payload under construction. A payload
    // arrives whole when the frame says it is self contained, and otherwise when
    // the accumulated bytes cover the envelope length the first frame declared.
    const size_t add = needs_decompression ? plain_length : payload_length;
    if (payload_size_ + add > MAX_PAYLOAD_SIZE) {
      return fail("Frame payload exceeds the maximum reassembled size");
    }
    // Guarded because indexing an empty vector is out of bounds even when the
    // copy is zero bytes long, which is the case for an empty frame.
    if (add > 0) {
      const size_t old_size = payload_.size();
      payload_.resize(old_size + add);
      memcpy(&payload_[old_size], needs_decompression ? &decompressed_[0] : frame_payload, add);
      payload_size_ += add;
    }
    accumulation_offset_ += frame_size;

    // A self contained frame ends the payload here; a multi frame payload ends
    // when the accumulated bytes cover the envelope length it declared.
    // Either way payload_ is handed out and reset for the next payload.
    const bool complete = self_contained || payload_complete();
    if (complete) {
      // A zero length payload leaves payload_ empty, and taking &payload_[0]
      // of an empty vector is out of bounds; a null pointer with a zero size
      // is the same thing every caller here expects.
      *payload = payload_.empty() ? NULL : &payload_[0];
      *size = payload_size_;
      payload_.clear();
      payload_size_ = 0;
      return RESULT_OK;
    }

    // This frame is a piece of a larger payload. Loop to read the next one: if
    // it has already arrived it is consumed here, otherwise the available
    // check above returns RESULT_NEED_MORE with payload_ still holding what
    // has been collected so far.
  }
}

}}} // namespace datastax::internal::core