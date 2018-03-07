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

#include "authentication/v1alpha1/policy.pb.h"
#include "common/common/logger.h"
#include "server/config/network/http_connection_manager.h"
#include "src/envoy/http/jwt_auth/jwt_authenticator.h"

namespace Envoy {
namespace Http {

// The authentication filter.
class AuthenticationFilter : public StreamDecoderFilter,
                             public JwtAuth::JwtAuthenticator::Callbacks,
                             public Logger::Loggable<Logger::Id::http> {
 public:
  AuthenticationFilter(const istio::authentication::v1alpha1::Policy& config,
                       Upstream::ClusterManager& cm);
  ~AuthenticationFilter();

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  FilterHeadersStatus decodeHeaders(HeaderMap& headers, bool) override;
  FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  FilterTrailersStatus decodeTrailers(HeaderMap&) override;
  void setDecoderFilterCallbacks(
      StreamDecoderFilterCallbacks& callbacks) override;

 private:
  // Implement the onDone() function of JwtAuth::Authenticator::Callbacks
  // interface.
  void onDone(const JwtAuth::Status& status);

  // Store the config.
  const istio::authentication::v1alpha1::Policy& config_;
  // The pointer to the http decoder call back.
  StreamDecoderFilterCallbacks* decoder_callbacks_;

  // jwt_auth config proto
  JwtAuth::Config::AuthFilterConfig jwt_config_;
  // jwt_auth per thread store
  JwtAuth::JwtAuthStore jwt_store_;
  // The JWT authenticator object.
  JwtAuth::JwtAuthenticator jwt_authn_;
};

}  // namespace Http
}  // namespace Envoy
