#include "crypto.hpp"

#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>

namespace fimd {

namespace {

struct MdCtxDel { void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); } };
struct PkeyDel { void operator()(EVP_PKEY* k) const { EVP_PKEY_free(k); } };
struct PkeyCtxDel { void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); } };
struct FileDel { void operator()(FILE* f) const { if (f) std::fclose(f); } };

using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDel>;
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;
using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDel>;
using FilePtr = std::unique_ptr<FILE, FileDel>;

std::string ssl_err() {
  unsigned long e = ERR_get_error();
  if (!e) return "unknown OpenSSL error";
  char buf[256];
  ERR_error_string_n(e, buf, sizeof buf);
  ERR_clear_error();
  return buf;
}

Pkey load_private(const std::string& path, std::string& err) {
  FilePtr f(std::fopen(path.c_str(), "re"));
  if (!f) { err = "cannot open " + path + ": " + std::strerror(errno); return nullptr; }
  Pkey k(PEM_read_PrivateKey(f.get(), nullptr, nullptr, nullptr));
  if (!k) { err = "cannot parse private key " + path + ": " + ssl_err(); return nullptr; }
  if (EVP_PKEY_id(k.get()) != EVP_PKEY_ED25519) { err = path + " is not an Ed25519 key"; return nullptr; }
  return k;
}

Pkey load_public(const std::string& path, std::string& err) {
  FilePtr f(std::fopen(path.c_str(), "re"));
  if (!f) { err = "cannot open " + path + ": " + std::strerror(errno); return nullptr; }
  Pkey k(PEM_read_PUBKEY(f.get(), nullptr, nullptr, nullptr));
  if (!k) { err = "cannot parse public key " + path + ": " + ssl_err(); return nullptr; }
  if (EVP_PKEY_id(k.get()) != EVP_PKEY_ED25519) { err = path + " is not an Ed25519 key"; return nullptr; }
  return k;
}

}  // namespace

std::string to_hex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s += d[p[i] >> 4];
    s += d[p[i] & 0xf];
  }
  return s;
}

std::string sha256_hex(const std::string& data) {
  uint8_t md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr);
  return to_hex(md, len);
}

bool sha256_fd(int fd, std::string& out_hex) {
  MdCtx ctx(EVP_MD_CTX_new());
  if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) return false;
  static thread_local uint8_t buf[1 << 16];
  for (;;) {
    ssize_t n = ::read(fd, buf, sizeof buf);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) break;
    if (EVP_DigestUpdate(ctx.get(), buf, static_cast<size_t>(n)) != 1) return false;
  }
  uint8_t md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  if (EVP_DigestFinal_ex(ctx.get(), md, &len) != 1) return false;
  out_hex = to_hex(md, len);
  return true;
}

bool generate_keypair(const std::string& priv_path, const std::string& pub_path, std::string& err) {
  PkeyCtx kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
  EVP_PKEY* raw = nullptr;
  if (!kctx || EVP_PKEY_keygen_init(kctx.get()) != 1 || EVP_PKEY_keygen(kctx.get(), &raw) != 1) {
    err = "key generation failed: " + ssl_err();
    return false;
  }
  Pkey key(raw);

  int pfd = ::open(priv_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (pfd < 0) { err = "cannot create " + priv_path + ": " + std::strerror(errno); return false; }
  FilePtr pf(::fdopen(pfd, "w"));
  if (!pf) { ::close(pfd); err = "fdopen failed"; return false; }
  if (PEM_write_PrivateKey(pf.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    err = "cannot write private key: " + ssl_err();
    return false;
  }
  if (std::fflush(pf.get()) != 0 || ::fsync(::fileno(pf.get())) != 0) { err = "cannot flush private key"; return false; }

  int ufd = ::open(pub_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
  if (ufd < 0) { err = "cannot create " + pub_path + ": " + std::strerror(errno); return false; }
  FilePtr uf(::fdopen(ufd, "w"));
  if (!uf) { ::close(ufd); err = "fdopen failed"; return false; }
  if (PEM_write_PUBKEY(uf.get(), key.get()) != 1) { err = "cannot write public key: " + ssl_err(); return false; }
  if (std::fflush(uf.get()) != 0) { err = "cannot flush public key"; return false; }
  return true;
}

bool sign_data(const std::string& priv_path, const std::string& data, Bytes& sig, std::string& err) {
  Pkey key = load_private(priv_path, err);
  if (!key) return false;
  MdCtx ctx(EVP_MD_CTX_new());
  if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
    err = "sign init failed: " + ssl_err();
    return false;
  }
  size_t siglen = 0;
  if (EVP_DigestSign(ctx.get(), nullptr, &siglen, reinterpret_cast<const uint8_t*>(data.data()), data.size()) != 1) {
    err = "sign failed: " + ssl_err();
    return false;
  }
  sig.assign(siglen, 0);
  if (EVP_DigestSign(ctx.get(), sig.data(), &siglen, reinterpret_cast<const uint8_t*>(data.data()), data.size()) != 1) {
    err = "sign failed: " + ssl_err();
    return false;
  }
  sig.resize(siglen);
  return true;
}

bool verify_data(const std::string& pub_path, const std::string& data, const Bytes& sig, std::string& err) {
  Pkey key = load_public(pub_path, err);
  if (!key) return false;
  MdCtx ctx(EVP_MD_CTX_new());
  if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
    err = "verify init failed: " + ssl_err();
    return false;
  }
  int rc = EVP_DigestVerify(ctx.get(), sig.data(), sig.size(),
                            reinterpret_cast<const uint8_t*>(data.data()), data.size());
  if (rc != 1) {
    ERR_clear_error();
    err = "signature does not match";
    return false;
  }
  return true;
}

}  // namespace fimd
