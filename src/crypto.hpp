#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace fimd {

using Bytes = std::vector<uint8_t>;

std::string to_hex(const uint8_t* p, size_t n);

// SHA-256 of an in-memory buffer, lowercase hex.
std::string sha256_hex(const std::string& data);

// SHA-256 of everything readable from fd starting at its current offset.
// Returns false on a read error.
bool sha256_fd(int fd, std::string& out_hex);

// Ed25519 key handling. Keys are PEM (PKCS#8 private, SPKI public).
// The private key file is created 0600 and never overwritten.
bool generate_keypair(const std::string& priv_path, const std::string& pub_path, std::string& err);
bool sign_data(const std::string& priv_path, const std::string& data, Bytes& sig, std::string& err);
bool verify_data(const std::string& pub_path, const std::string& data, const Bytes& sig, std::string& err);

}  // namespace fimd
