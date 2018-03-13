/* Copyright 2018 Istio Authors. All Rights Reserved.
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

#pragma once

#include "common/common/logger.h"
#include "envoy/server/filter_config.h"
#include "envoy/thread_local/thread_local.h"
#include "src/envoy/http/jwt_auth/auth_store.h"
#include "src/envoy/http/jwt_auth/config.pb.h"

namespace Envoy {
namespace Http {
namespace IstioAuthn {

enum JwtStoreType { PEER_STORE = 0, ORIGIN_STORE = 1 };

// Store the JwtAuthStoreFactory objects
class JwtAuthnFactoryStore : public Logger::Loggable<Logger::Id::config> {
 public:
  JwtAuthnFactoryStore(Server::Configuration::FactoryContext &context)
      : context_(context) {}

  // Get per-thread auth store object.
  std::map<JwtStoreType, std::vector<Envoy::Http::JwtAuth::JwtAuthStoreFactory>>
      &store() {
    return store_;
  }

  // Add an AuthFilterConfig to the store
  void addToStore(JwtStoreType type,
                  Envoy::Http::JwtAuth::Config::AuthFilterConfig &config) {
    std::string config_str;
    config.SerializeToString(&config_str);
    if (config_.find(type) != config_.end() &&
        config_[type].find(config_str) != config_[type].end()) {
      ENVOY_LOG(debug, "{}: AuthFilterConfig exists already", __FUNCTION__);
      return;
    }

    if (config_.find(type) == config_.end()) {
      // Add set of AuthFilterConfig as string for the given type
      config_[type] = std::set<std::string>();
    }
    // Add the config_str to the set
    config_[type].insert(config_str);

    if (store_.find(type) == store_.end()) {
      store_[type] = std::vector<Envoy::Http::JwtAuth::JwtAuthStoreFactory>();
    }
    // Add auth_store_factory to JwtAuthStoreFactory set
    // store_[type].push_back(Envoy::Http::JwtAuth::JwtAuthStoreFactory(config,
    // context_));
    store_[type].emplace_back(config, context_);
    ENVOY_LOG(debug, "{}: add a JwtAuthStoreFactory to the type {}",
              __FUNCTION__, type);
  }

 private:
  // Store the FactoryContext object reference
  Server::Configuration::FactoryContext &context_;

  // Store AuthFilterConfig as string
  std::map<JwtStoreType, std::set<std::string>> config_{};

  // Store the JwtAuthStoreFactory objects
  std::map<JwtStoreType, std::vector<Envoy::Http::JwtAuth::JwtAuthStoreFactory>>
      store_{};
};

// Store the JwtAuthnStore objects as thread local
class JwtAuthnStore : public ThreadLocal::ThreadLocalObject,
                      public Logger::Loggable<Logger::Id::config> {
 public:
  JwtAuthnStore() {}

  // Get per-thread auth store object.
  std::map<JwtStoreType, std::vector<Envoy::Http::JwtAuth::JwtAuthStore>>
      &store() {
    return store_;
  }

  // Add an AuthFilterConfig to the store
  void addToStore(JwtStoreType type,
                  Envoy::Http::JwtAuth::Config::AuthFilterConfig &config) {
    std::string config_str;
    config.SerializeToString(&config_str);
    if (config_.find(type) != config_.end() &&
        config_[type].find(config_str) != config_[type].end()) {
      ENVOY_LOG(debug, "{}: AuthFilterConfig exists already", __FUNCTION__);
      return;
    }

    if (config_.find(type) == config_.end()) {
      // Add set of AuthFilterConfig as string for the given type
      config_[type] = std::set<std::string>();
    }
    // Add the config_str to the set
    config_[type].insert(config_str);

    Envoy::Http::JwtAuth::JwtAuthStore auth_store(config);
    if (store_.find(type) == store_.end()) {
      // Add set of JwtAuthStore for the given type
      store_[type] = std::vector<Envoy::Http::JwtAuth::JwtAuthStore>();
    }
    // Add auth_store to JwtAuthStore set
    store_[type].push_back(std::move(auth_store));
    ENVOY_LOG(debug, "{}: add a JwtAuthStore to the type {}", __FUNCTION__,
              type);
  }

 private:
  // Store AuthFilterConfig as string
  std::map<JwtStoreType, std::set<std::string>> config_{};

  // Store the JwtAuthStore objects
  std::map<JwtStoreType, std::vector<Envoy::Http::JwtAuth::JwtAuthStore>>
      store_{};
};

// The factory to create per-thread JwtAuthnStore object.
class JwtAuthnStoreFactory : public Logger::Loggable<Logger::Id::config> {
 public:
  // Create JwtAuthnStoreFactory
  JwtAuthnStoreFactory(Server::Configuration::FactoryContext &context)
      : tls_(context.threadLocal().allocateSlot()) {
    ENVOY_LOG(info, "Creat JwtAuthnStoreFactory");
    tls_->set(
        [this](Event::Dispatcher &) -> ThreadLocal::ThreadLocalObjectSharedPtr {
          return std::make_shared<JwtAuthnStore>();
        });
  }

  // Get per-thread auth store object.
  JwtAuthnStore &store() { return tls_->getTyped<JwtAuthnStore>(); }

 private:
  // Thread local slot to store per-thread JwtAuthnStore object
  ThreadLocal::SlotPtr tls_;
};

}  // namespace IstioAuthn
}  // namespace Http
}  // namespace Envoy
