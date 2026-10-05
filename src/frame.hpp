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

#ifndef DATASTAX_INTERNAL_FRAME_HPP
#define DATASTAX_INTERNAL_FRAME_HPP

#include "buffer.hpp"
#include "constants.hpp"
#include "string.hpp"
#include "types.hpp"
#include "vector.hpp"

namespace datastax { namespace internal { namespace core {

/**
 * The compression algorithm negotiated for protocol v5 frame payloads.
 *
 * LZ4 is the only algorithm the v5 specification allows. Snappy was dropped
 * in v5 and Cassandra rejects it outright, so it is not offered here.
 */
enum FrameCompression {
  /** Payloads are sent as-is using the 6 byte header. */
  FRAME_COMPRESSION_NONE,
  /** Payloads are LZ4 compressed using the 8 byte header. */
  FRAME_COMPRESSION_LZ4
};

/** Whether this build can negotiate LZ4 frame compression. */
bool frame_compression_available(FrameCompression compression);

/**
 * Codec for the protocol v5 frame format.
 *
 * A frame wraps a stream of CQL envelopes and adds integrity checking plus a
 * bound on how much data must be buffered before a message can be processed:
 *
 *   [ 6 byte header ][ payload (<= MAX_PAYLOAD_LENGTH bytes) ][ 4 byte CRC32 trailer ]
 *
 * The header is a 3 byte little-endian integer holding a 17 bit payload
 * length, a 1 bit "self contained" flag and 6 padding bits, followed by a 3
 * byte CRC24 of those first 3 bytes. The trailer is the CRC32 of the payload
 * as a little-endian integer. See the native protocol v5 specification, §2.1.
 *
 * When LZ4 compression has been negotiated the frame uses an 8 byte header
 * instead (§2.2). It packs a 17 bit compressed length, a 17 bit uncompressed
 * length, a 1 bit "self contained" flag and 5 padding bits into a 5 byte
 * little-endian integer, followed by a 3 byte CRC24 of those first 5 bytes:
 *
 *   [ 8 byte header ][ payload (<= MAX_PAYLOAD_LENGTH bytes) ][ 4 byte CRC32 trailer ]
 *
 * The trailer covers the payload as transmitted, so it is the CRC32 of the
 * *compressed* bytes. An uncompressed length of zero signals that the payload
 * is stored as-is and must not be decompressed; the on-wire payload length
 * always comes from the compressed length field. Note that the specification's
 * prose gets this backwards, claiming a compressed length of zero signals an
 * uncompressed payload; Cassandra's own decoder agrees with the behaviour
 * described here.
 *
 * The "self contained" flag does not mean "last frame of the payload". It means
 * "this frame carries only whole envelopes", and a frame that is part of a
 * multi frame message has the flag clear *including the final frame*. Cassandra
 * terminates a multi frame message by accumulated frame size, not by the flag,
 * so marking the last frame as self contained makes the server try to parse an
 * envelope header out of a fragment and fail the connection. See
 * FrameDecoder for how a multi frame payload's end is detected.
 *
 * Because the header size is fixed for the life of a connection, a decoder
 * must be told which format to expect rather than inferring it per frame.
 */
class FrameCodec {
public:
  /** Header (including its CRC24) for the uncompressed format. */
  static const size_t UNCOMPRESSED_HEADER_SIZE = 6;

  /** Header (including its CRC24) for the LZ4 compressed format. */
  static const size_t COMPRESSED_HEADER_SIZE = 8;

  /** Size of the CRC32 payload trailer. */
  static const size_t TRAILER_SIZE = 4;

  /** Total framing overhead added to a single self contained frame. */
  static const size_t OVERHEAD = UNCOMPRESSED_HEADER_SIZE + TRAILER_SIZE;

  /** Total framing overhead for a single compressed frame. */
  static const size_t COMPRESSED_OVERHEAD = COMPRESSED_HEADER_SIZE + TRAILER_SIZE;

  /**
   * The maximum payload of a single frame.
   *
   * A whole frame, header and trailer included, must fit inside the 2^17 byte
   * frame budget, so the payload bound is 2^17 minus the largest header plus
   * trailer pair. The Java driver and server derive the same number.
   */
  static const size_t MAX_PAYLOAD_LENGTH = (1 << 17) - COMPRESSED_OVERHEAD;

  /**
   * Smallest header we can decode before knowing the payload length.
   *
   * This is the uncompressed header; a compressed connection can always read
   * at least this much before it has the payload length.
   */
  static const size_t MIN_HEADER_SIZE = UNCOMPRESSED_HEADER_SIZE;

  /** The header size used by a connection with the given compression. */
  static size_t header_size(FrameCompression compression) {
    return compression == FRAME_COMPRESSION_NONE ? UNCOMPRESSED_HEADER_SIZE
                                                 : COMPRESSED_HEADER_SIZE;
  }

  /** The framing overhead for a connection with the given compression. */
  static size_t overhead(FrameCompression compression) {
    return compression == FRAME_COMPRESSION_NONE ? OVERHEAD : COMPRESSED_OVERHEAD;
  }

  /**
   * The number of framing bytes added to a payload of the given size.
   *
   * @param payload_size The total payload to be framed.
   * @param compression The negotiated compression.
   * @return The overhead, including any additional headers needed to split
   * payloads larger than MAX_PAYLOAD_LENGTH.
   */
  static size_t overhead(size_t payload_size,
                        FrameCompression compression = FRAME_COMPRESSION_NONE);

  /**
   * Write the header for an uncompressed, self contained frame.
   *
   * @param output At least UNCOMPRESSED_HEADER_SIZE writable bytes.
   * @param payload_size The payload length; must be <= MAX_PAYLOAD_LENGTH.
   */
  static void encode_header(char* output, size_t payload_size);

  /**
   * Write the header for an uncompressed frame that is (or is not) self
   * contained.
   *
   * @param output At least UNCOMPRESSED_HEADER_SIZE writable bytes.
   * @param payload_size The payload length; must be <= MAX_PAYLOAD_LENGTH.
   * @param self_contained False when this frame is one piece of a larger
   * payload that continues in subsequent frames.
   */
  static void encode_header(char* output, size_t payload_size, bool self_contained);

  /**
   * Write the header for an LZ4 frame.
   *
   * @param output At least COMPRESSED_HEADER_SIZE writable bytes.
   * @param compressed_size The on-wire payload length; must be <=
   * MAX_PAYLOAD_LENGTH.
   * @param uncompressed_size The length after decompression, or 0 when the
   * payload is stored uncompressed.
   * @param self_contained False when this frame is one piece of a larger
   * payload that continues in subsequent frames.
   */
  static void encode_compressed_header(char* output, size_t compressed_size,
                                       size_t uncompressed_size, bool self_contained);

  /**
   * Write a payload CRC32 as a little-endian trailer.
   *
   * @param output At least TRAILER_SIZE writable bytes.
   * @param crc The payload checksum.
   */
  static void encode_trailer(char* output, uint32_t crc);

  /**
   * Frame the concatenation of the given buffers, appending the resulting frame
   * buffers to `output` (which is cleared first).
   *
   * Buffers are not copied when the payload fits in a single frame. Payloads
   * larger than MAX_PAYLOAD_LENGTH are split over several frames, each marked
   * as not self contained except for the last.
   *
   * @param payload The buffers holding the bytes to frame.
   * @param output Receives the framed buffers.
   * @param compression The negotiated compression.
   * @return The total number of framed bytes.
   */
  static int32_t encode(const BufferVec& payload, BufferVec* output,
                        FrameCompression compression = FRAME_COMPRESSION_NONE);

  /**
   * Frame the concatenation of the buffers in the range [start, end),
   * replacing the contents of `output` (which is cleared first).
   *
   * This lets a caller frame a sub-range of an existing buffer list in place,
   * which is how a request's already encoded envelope is wrapped.
   *
   * @return The total number of framed bytes.
   */
  static int32_t encode(const BufferVec& payload, size_t start, size_t end,
                        BufferVec* output,
                        FrameCompression compression = FRAME_COMPRESSION_NONE);

  /**
   * Frame a contiguous payload, appending the resulting frame buffers to
   * `output` (which is cleared first).
   *
   * @param payload The bytes to frame.
   * @param size The number of bytes to frame.
   * @param output Receives the framed buffers.
   * @param compression The negotiated compression.
   * @return The total number of framed bytes.
   */
  static int32_t encode(const char* payload, size_t size, BufferVec* output,
                        FrameCompression compression = FRAME_COMPRESSION_NONE);

  /**
   * Frame a contiguous payload into a single string, mostly useful for tests
   * and for callers that already hold the payload in one piece.
   */
  static String encode(const String& payload,
                       FrameCompression compression = FRAME_COMPRESSION_NONE);

/**
   * Compress a contiguous payload with LZ4.
   *
   * @param payload The bytes to compress.
   * @param size The number of bytes to compress; must be <=
   * MAX_PAYLOAD_LENGTH.
   * @param output Receives the compressed bytes; must have room for at least
   * compress_bound(size) bytes.
   * @return The number of compressed bytes, or a negative value on failure.
   */
  static int32_t compress(const char* payload, size_t size, char* output);

  /**
   * Compress the concatenation of the buffers in the range [start, end).
   *
   * The buffers are copied into a contiguous block because LZ4 needs to see
   * the payload as one piece.
   *
   * @param output Receives the compressed bytes; must have room for at least
   * compress_bound(total) bytes.
   * @return The number of compressed bytes, or a negative value on failure.
   */
  static int32_t compress(const BufferVec& payload, size_t start, size_t end,
                          char* output);

  /**
   * Decompress an LZ4 payload.
   *
   * @param payload The compressed bytes.
   * @param size The number of compressed bytes.
   * @param uncompressed_size The expected size after decompression.
   * @param output Receives the decompressed bytes; must have room for at least
   * uncompressed_size bytes.
   * @return The number of decompressed bytes, or a negative value on failure.
   */
  static int32_t decompress(const char* payload, size_t size,
                            size_t uncompressed_size, char* output);

  /**
   * The upper bound on the compressed size of a payload of the given length.
   *
   * LZ4's worst case expansion is used so callers can size a buffer up front.
   */
  static size_t compress_bound(size_t size);

  /** The CRC32 of a payload, as written to the trailer. */
  static uint32_t payload_crc(const char* data, size_t size);

  /** The CRC32 of the concatenation of the given buffers. */
  static uint32_t payload_crc(const BufferVec& payload, size_t start, size_t end);

  /** Write a 24 bit unsigned integer in little-endian order. */
  static void encode_uint24(char* output, uint32_t value);

  /** Read a 24 bit unsigned little-endian integer. */
  static uint32_t decode_uint24(const char* input);

  /** Write a 32 bit unsigned integer in little-endian order. */
  static void encode_uint32(char* output, uint32_t value);

  /** Read a 32 bit unsigned little-endian integer. */
  static uint32_t decode_uint32(const char* input);
};

/**
 * Incremental decoder for the protocol v5 frame format.
 *
 * Bytes are handed to feed() in whatever chunks the socket produces and
 * complete payloads are pulled out with next(). Payloads that span several
 * frames (non self contained frames) are transparently reassembled.
 *
 * The decoder is fixed to one compression mode for its lifetime because the
 * header size is not self describing: there is no bit that distinguishes a 6
 * byte header from an 8 byte one, so the two cannot be told apart from the
 * bytes alone.
 */
class FrameDecoder {
public:
  enum Result {
    /** A complete payload is available via next()'s out parameters. */
    RESULT_OK,
    /** More bytes are required before a payload can be produced. */
    RESULT_NEED_MORE,
    /** The byte stream is corrupt and the connection must be closed. */
    RESULT_ERROR
  };

  /** Guards against a peer streaming unbounded non self contained frames. */
  static const size_t MAX_PAYLOAD_SIZE = 256 * 1024 * 1024;

  /**
   * @param compression The compression negotiated for this connection.
   */
  explicit FrameDecoder(FrameCompression compression = FRAME_COMPRESSION_NONE);

  /** Discard all buffered state. */
  void reset();

  /** Append bytes read from the socket. */
  void feed(const char* data, size_t size);

/**
 * Attempt to produce the next complete payload of de-framed envelope bytes.
   *
   * A frame whose self contained flag is set carries only whole envelopes, so
   * its payload is complete as soon as it arrives. A frame without the flag is
   * one piece of a payload that continues in later frames -- and so is every
   * following piece, the last one included -- so the payload's end cannot be
   * read off the frame headers. It is found instead by decoding the length the
   * accumulated envelope header declares, which is how the server tracks it.
   *
   * A single call may consume several frames when the payload was split.
   *
   * The returned pointer aliases either the decoder's internal buffer or its
   * accumulation buffer, so it is only valid until the next call to next() or
   * feed(). Consume it before calling either.
   *
   * @param payload Set to the de-framed bytes when returning RESULT_OK.
   * @param size Set to the length of `payload` when returning RESULT_OK.
   * @return The result of the attempt.
   */
  Result next(const char** payload, size_t* size);

  /** The reason for the most recent RESULT_ERROR. */
  const char* error() const { return error_.c_str(); }

  /** The compression this decoder was configured for. */
  FrameCompression compression() const { return compression_; }

private:
  Result fail(const char* message);
  Result fail_crc(const char* what, uint32_t expected, uint32_t actual);

  /**
   * The number of envelope bytes the payload accumulated so far declares, or 0
   * when the header is not available yet.
   */
  size_t declared_payload_size() const;

  /** Whether the accumulated payload holds at least one whole envelope. */
  bool payload_complete() const;

private:
  FrameCompression compression_;
  Vector<char> accumulation_;
  size_t accumulation_offset_;
  Vector<char> payload_;
  size_t payload_size_;
  // Holds the decompressed bytes when a self contained frame was compressed;
  // the payload handed to the caller points into this buffer.
  Vector<char> decompressed_;
  String error_;
};

}}} // namespace datastax::internal::core

#endif