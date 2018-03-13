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

typedef std::map<JwtStoreType,
                 std::vector<Envoy::Http::JwtAuth::JwtAuthStoreFactory>>
    JwtMultiFactoryStore;

// Store the JwtAuthStoreFactory objects
class JwtAuthnFactoryStore : public Logger::Loggable<Logger::Id::config> {
 public:
  JwtAuthnFactoryStore(Server::Configuration::FactoryContext &context)
      : context_(context) {}

  // Get the reference of the JwtAuthStoreFactory objects
  JwtMultiFactoryStore &store() { return store_; }

  // Add an AuthFilterConfig to the store.
  // JwtStoreType type is an enum of PEER_STORE and ORIGIN_STORE.
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
      // Add set of AuthFilterConfig as strings for the given type
      config_[type] = std::set<std::string>();
    }
    // Add config_str to the set
    config_[type].insert(config_str);
    if (store_.find(type) == store_.end()) {
      store_[type] = std::vector<Envoy::Http::JwtAuth::JwtAuthStoreFactory>();
    }
    // Add a JwtAuthStoreFactory
    store_[type].emplace_back(config, context_);
    ENVOY_LOG(debug, "{}: added a JwtAuthStoreFactory to the type {}",
              __FUNCTION__, type);
  }

 private:
  // Store the FactoryContext object reference
  Server::Configuration::FactoryContext &context_;

  // Store AuthFilterConfig as string
  std::map<JwtStoreType, std::set<std::string>> config_{};

  // Store the JwtAuthStoreFactory objects
  JwtMultiFactoryStore store_{};
};

}  // namespace IstioAuthn
}  // namespace Http
}  // namespace Envoy
