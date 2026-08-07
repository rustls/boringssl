// Copyright 2025 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <benchmark/benchmark.h>

#include <openssl/base.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include "./internal.h"

BSSL_NAMESPACE_BEGIN
namespace {

void BM_SpeedECDH(benchmark::State &state, const EC_GROUP *group) {
  UniquePtr<EC_KEY> peer_key(EC_KEY_new());
  if (!peer_key || !EC_KEY_set_group(peer_key.get(), group) ||
      !EC_KEY_generate_key(peer_key.get())) {
    state.SkipWithError("peer keygen failed.");
    return;
  }

  const EC_POINT *peer_pub = EC_KEY_get0_public_key(peer_key.get());

  UniquePtr<EC_KEY> key(EC_KEY_new());
  if (!key || !EC_KEY_set_group(key.get(), group) ||
      !EC_KEY_generate_key(key.get())) {
    state.SkipWithError("self keygen failed.");
    return;
  }

  uint8_t secret[66];
  size_t secret_len = (EC_GROUP_get_degree(group) + 7) / 8;
  if (secret_len > sizeof(secret)) {
    state.SkipWithError("secret length exceeds buffer size.");
    return;
  }

  for (auto _ : state) {
    benchmark::ClobberMemory();
    benchmark::DoNotOptimize(peer_pub);

    int res =
        ECDH_compute_key(secret, secret_len, peer_pub, key.get(), nullptr);
    if (res < 0) {
      state.SkipWithError("ECDH_compute_key failed.");
      return;
    }

    benchmark::DoNotOptimize(secret);
    benchmark::DoNotOptimize(res);
  }
}

BSSL_BENCH_LAZY_REGISTER() {
  BENCHMARK_CAPTURE(BM_SpeedECDH, p224, EC_group_p224())
      ->Apply(bench::SetThreads);
  BENCHMARK_CAPTURE(BM_SpeedECDH, p256, EC_group_p256())
      ->Apply(bench::SetThreads);
  BENCHMARK_CAPTURE(BM_SpeedECDH, p384, EC_group_p384())
      ->Apply(bench::SetThreads);
  BENCHMARK_CAPTURE(BM_SpeedECDH, p521, EC_group_p521())
      ->Apply(bench::SetThreads);
}

}  // namespace
BSSL_NAMESPACE_END
