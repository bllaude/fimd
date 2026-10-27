// Unit tests for src/crypto.cpp: SHA-256, Ed25519 keygen/sign/verify.
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "test_framework.hpp"
#include "util.hpp"

using namespace fimd;

namespace {

void write_junk_file(const std::string& path, const std::string& data) {
  std::ofstream os(path, std::ios::binary);
  os << data;
}

bool is_lower_hex(const std::string& s, size_t n) {
  if (s.size() != n) return false;
  for (char c : s) {
    bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    if (!ok) return false;
  }
  return true;
}

}  // namespace

TEST(Crypto, ToHexFormatting) {
  const uint8_t empty[] = {};
  EXPECT_EQ(to_hex(empty, 0), std::string());

  const uint8_t v1[] = {0x00, 0xff, 0x0a, 0xa5, 0x80};
  EXPECT_EQ(to_hex(v1, sizeof v1), std::string("00ff0aa580"));

  const uint8_t v2[] = {0xde, 0xad, 0xbe, 0xef};
  EXPECT_EQ(to_hex(v2, sizeof v2), "deadbeef");
}

TEST(Crypto, Sha256KnownVectors) {
  // Well-known FIPS 180-4 test vectors.
  EXPECT_EQ(sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  EXPECT_EQ(sha256_hex("hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
  // 56-character input exercises the padding boundary (two blocks).
  EXPECT_EQ(sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "8224557d13e0ee42954a7ed380701e5e53b0ebc8f604ed89c7b7c90c9b57f0bd");
  EXPECT_TRUE(is_lower_hex(sha256_hex("x"), 64));
}

TEST(Crypto, Sha256FdMatchesSha256Hex) {
  tf::TempDir tmp("fimd_crypto_fd");
  ASSERT_TRUE(tmp.ok());
  const std::string p = tmp / "blob";
  const std::string content = std::string(100000, 'A') + "tail\n";  // crosses buffer boundaries
  write_junk_file(p, content);

  int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
  ASSERT_TRUE(fd >= 0);
  std::string hex;
  ASSERT_TRUE(sha256_fd(fd, hex));
  ::close(fd);
  EXPECT_EQ(hex, sha256_hex(content));

  // An invalid fd fails cleanly.
  std::string h2;
  EXPECT_FALSE(sha256_fd(-1, h2));
}

TEST(Crypto, GenerateKeypairWritesPemFilesWithTightPrivMode) {
  tf::TempDir tmp("fimd_crypto_keygen");
  ASSERT_TRUE(tmp.ok());
  const std::string priv = tmp / "k.pem";
  const std::string pub = tmp / "k.pub";
  std::string err;
  ASSERT_TRUE(generate_keypair(priv, pub, err));
  EXPECT_TRUE(err.empty());

  struct stat st;
  ASSERT_TRUE(::stat(priv.c_str(), &st) == 0);
  EXPECT_EQ(static_cast<int>(st.st_mode & 07777), 0600);
  ASSERT_TRUE(::stat(pub.c_str(), &st) == 0);
  EXPECT_EQ(static_cast<int>(st.st_mode & 07777), 0644);

  std::string privtext, pubtext;
  ASSERT_TRUE(read_file(priv, privtext));
  ASSERT_TRUE(read_file(pub, pubtext));
  EXPECT_TRUE(privtext.find("PRIVATE KEY") != std::string::npos);
  EXPECT_TRUE(pubtext.find("PUBLIC KEY") != std::string::npos);
}

TEST(Crypto, KeygenRefusesToOverwriteExistingKey) {
  tf::TempDir tmp("fimd_crypto_overwrite");
  ASSERT_TRUE(tmp.ok());
  const std::string priv = tmp / "k.pem";
  const std::string pub = tmp / "k.pub";
  std::string err;
  ASSERT_TRUE(generate_keypair(priv, pub, err));
  std::string before;
  ASSERT_TRUE(read_file(priv, before));

  EXPECT_FALSE(generate_keypair(priv, pub, err));  // O_EXCL must protect the key
  EXPECT_FALSE(err.empty());
  std::string after;
  ASSERT_TRUE(read_file(priv, after));
  EXPECT_EQ(after, before);  // untouched
}

TEST(Crypto, SignVerifyRoundtripAndTamperDetection) {
  tf::TempDir tmp("fimd_crypto_sign");
  ASSERT_TRUE(tmp.ok());
  const std::string priv = tmp / "k.pem";
  const std::string pub = tmp / "k.pub";
  std::string err;
  ASSERT_TRUE(generate_keypair(priv, pub, err));

  const std::string msg = "fimd-baseline v1\ncreated\t2026-10-27T00:00:00.000Z\nroot\t/etc\n";
  Bytes sig;
  ASSERT_TRUE(sign_data(priv, msg, sig, err));
  EXPECT_EQ(sig.size(), static_cast<unsigned long>(64));  // raw Ed25519 signature

  EXPECT_TRUE(verify_data(pub, msg, sig, err));

  // Any single-byte change to the message invalidates the signature.
  std::string tampered = msg;
  tampered[10] = tampered[10] == 'X' ? 'Y' : 'X';
  err.clear();
  EXPECT_FALSE(verify_data(pub, tampered, sig, err));
  EXPECT_FALSE(err.empty());

  // So does a change to the signature itself.
  Bytes badsig = sig;
  badsig[0] ^= 0x01;
  EXPECT_FALSE(verify_data(pub, msg, badsig, err));

  // Empty messages sign and verify fine (Ed25519 is not digest-prefixed).
  Bytes esig;
  ASSERT_TRUE(sign_data(priv, "", esig, err));
  EXPECT_TRUE(verify_data(pub, "", esig, err));
}

TEST(Crypto, VerifyFailsWithDifferentKeypair) {
  tf::TempDir tmp("fimd_crypto_wrongkey");
  ASSERT_TRUE(tmp.ok());
  std::string err;
  ASSERT_TRUE(generate_keypair(tmp / "a.pem", tmp / "a.pub", err));
  ASSERT_TRUE(generate_keypair(tmp / "b.pem", tmp / "b.pub", err));

  Bytes sig;
  ASSERT_TRUE(sign_data(tmp / "a.pem", "payload", sig, err));
  EXPECT_FALSE(verify_data(tmp / "b.pub", "payload", sig, err));  // wrong public key
  EXPECT_TRUE(verify_data(tmp / "a.pub", "payload", sig, err));
}

TEST(Crypto, KeyFileErrorPaths) {
  tf::TempDir tmp("fimd_crypto_errors");
  ASSERT_TRUE(tmp.ok());
  std::string err;
  Bytes sig;

  // Missing private key file.
  EXPECT_FALSE(sign_data(tmp / "nope.pem", "data", sig, err));
  EXPECT_FALSE(err.empty());

  // Missing public key file.
  EXPECT_FALSE(verify_data(tmp / "nope.pub", "data", sig, err));

  // Garbage where a PEM key should be.
  write_junk_file(tmp / "junk.pem", "not a key at all\n");
  write_junk_file(tmp / "junk.pub", "not a key at all\n");
  err.clear();
  EXPECT_FALSE(sign_data(tmp / "junk.pem", "data", sig, err));
  EXPECT_FALSE(err.empty());
  err.clear();
  EXPECT_FALSE(verify_data(tmp / "junk.pub", "data", sig, err));
  EXPECT_FALSE(err.empty());

  // A valid RSA key must be rejected: fimd only speaks Ed25519.
  // (Skip if openssl CLI is unavailable in this environment.)
  const std::string cmd =
      "command -v openssl >/dev/null 2>&1 && "
      "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out '" +
      tmp.path() + "/rsa.pem' 2>/dev/null && openssl pkey -in '" + tmp.path() +
      "/rsa.pem' -pubout -out '" + tmp.path() + "/rsa.pub' 2>/dev/null";
  int rc = ::system(cmd.c_str());
  if (rc == 0) {
    err.clear();
    EXPECT_FALSE(sign_data(tmp / "rsa.pem", "data", sig, err));
    EXPECT_TRUE(err.find("not an Ed25519") != std::string::npos);
    Bytes rsasig;
    err.clear();
    EXPECT_FALSE(verify_data(tmp / "rsa.pub", "data", rsasig, err));
    EXPECT_TRUE(err.find("not an Ed25519") != std::string::npos);
  }
}
