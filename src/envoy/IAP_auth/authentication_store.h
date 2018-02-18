/* Copyright 2017 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef AUTHENTICATION_STORE_H
#define AUTHENTICATION_STORE_H

#include "common/common/logger.h"
#include "envoy/server/filter_config.h"
#include "envoy/thread_local/thread_local.h"
#include "src/envoy/IAP_auth/policy.pb.validate.h"
#include "src/envoy/IAP_auth/pubkey_cache.h"

namespace Envoy {
namespace Http {
namespace Auth {

// The authentication store stores config and caches.
// It only has pubkey_cache for JWT now. In the future it will have token cache.
// It is per-thread and stored in thread local.
class AuthenticationStore : public ThreadLocal::ThreadLocalObject {
 public:
  // Load the config from envoy config.
  AuthenticationStore(const istio::authentication::v1alpha1::Policy& config)
      : config_(config) {}

  // Get the Config.
  const istio::authentication::v1alpha1::Policy& config() const {
    return config_;
  }

  // Get the pubkey cache.
  // PubkeyCache& pubkey_cache() { return pubkey_cache_; }

 private:
  // Store the config.
  const istio::authentication::v1alpha1::Policy& config_;
  // The public key cache, indexed by issuer.
  // PubkeyCache pubkey_cache_;
};

// The factory to create per-thread auth store object.
class AuthenticationStoreFactory : public Logger::Loggable<Logger::Id::config> {
 public:
  AuthenticationStoreFactory(
      const istio::authentication::v1alpha1::Policy& config,
      Server::Configuration::FactoryContext& context)
      : config_(config), tls_(context.threadLocal().allocateSlot()) {
    tls_->set(
        [this](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
          return std::make_shared<AuthenticationStore>(config_);
        });
    ENVOY_LOG(info, "Loaded Authentication Policy Config: {}",
              config_.DebugString());
  }

  // Get per-thread auth store object.
  AuthenticationStore& store() { return tls_->getTyped<AuthenticationStore>(); }

 private:
  // The authentication policy config.
  istio::authentication::v1alpha1::Policy config_;
  // Thread local slot to store per-thread auth store
  ThreadLocal::SlotPtr tls_;
};

}  // namespace Auth
}  // namespace Http
}  // namespace Envoy

#endif  // AUTHENTICATION_STORE_H
