#ifndef DSTU_CPP_BYTES_HPP
#define DSTU_CPP_BYTES_HPP

#include <cstddef>
#include <cstdint>

namespace dstu {

/// A non-owning view over a contiguous, readable byte buffer - stands in for std::span<const
/// std::byte> (this binding targets C++17, one standard ahead of std::span's own C++20 floor).
/// Implicitly constructible from any contiguous byte container (std::vector<uint8_t>,
/// std::array<uint8_t, N>, ...) so call sites can pass either directly.
class ByteView {
 public:
  ByteView() = default;
  ByteView(const std::uint8_t *data, std::size_t size) : data_(size == 0 ? nullptr : data), size_(size) {}

  template <typename Container>
  ByteView(const Container &c)  // NOLINT(google-explicit-constructor)
      : ByteView(reinterpret_cast<const std::uint8_t *>(c.data()), c.size()) {}

  const std::uint8_t *data() const { return data_; }
  std::size_t size() const { return size_; }

 private:
  const std::uint8_t *data_ = nullptr;
  std::size_t size_ = 0;
};

/// Same as ByteView, but over a writable buffer - for an output parameter this wrapper fills in
/// place (e.g. AuthKey::Bytes(MutableByteView)).
class MutableByteView {
 public:
  MutableByteView() = default;
  MutableByteView(std::uint8_t *data, std::size_t size) : data_(size == 0 ? nullptr : data), size_(size) {}

  template <typename Container>
  MutableByteView(Container &c)  // NOLINT(google-explicit-constructor)
      : MutableByteView(reinterpret_cast<std::uint8_t *>(c.data()), c.size()) {}

  std::uint8_t *data() const { return data_; }
  std::size_t size() const { return size_; }

 private:
  std::uint8_t *data_ = nullptr;
  std::size_t size_ = 0;
};

}  // namespace dstu

#endif  // DSTU_CPP_BYTES_HPP
