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

#include "src/envoy/http/authn/http_filter.h"
//#include <memory>
#include "common/http/utility.h"
#include "src/envoy/http/authn/mtls_authentication.h"

namespace Envoy {
namespace Http {

AuthenticationFilter::AuthenticationFilter(
    const istio::authentication::v1alpha1::Policy& config,
    Upstream::ClusterManager& cm,
    std::map<IstioAuthn::JwtStoreType,
             std::vector<Envoy::Http::JwtAuth::JwtAuthStoreFactory>>& jwt_store)
    : config_(config), cm_(cm), jwt_store_(jwt_store) {}

AuthenticationFilter::~AuthenticationFilter() {}

void AuthenticationFilter::onDestroy() {
  ENVOY_LOG(debug, "Called AuthenticationFilter : {}", __func__);
  if (jwt_auth_ != nullptr) {
    jwt_auth_->onDestroy();
  }
}

FilterHeadersStatus AuthenticationFilter::decodeHeaders(HeaderMap& headers,
                                                        bool) {
  ENVOY_LOG(debug, "Called AuthenticationFilter : {}", __func__);

  int peer_size = config_.peers_size();
  ENVOY_LOG(debug, "AuthenticationFilter: {} config.peers_size()={}", __func__,
            peer_size);
  if (peer_size > 0) {
    const auto& m = config_.peers()[0];
    if (m.has_mtls()) {
      ENVOY_LOG(debug, "AuthenticationFilter: {} this connection requires mTLS",
                __func__);
      MtlsAuthentication mtls_authn(decoder_callbacks_->connection());
      if (mtls_authn.IsMutualTLS() == false) {
        // In prototype, only log the authentication policy violation.
        ENVOY_LOG(error,
                  "AuthenticationFilter: authn policy requires mTLS but the "
                  "connection is not mTLS!");
      } else {
        ENVOY_LOG(debug, "AuthenticationFilter: the connection is mTLS.");
        std::string user, ip;
        int port = 0;
        bool ret = false;
        ret = mtls_authn.GetSourceUser(&user);
        if (ret) {
          ENVOY_LOG(debug, "AuthenticationFilter: the source user is {}", user);
        } else {
          ENVOY_LOG(error,
                    "AuthenticationFilter: GetSourceUser() returns false!");
        }
        ret = mtls_authn.GetSourceIpPort(&ip, &port);
        if (ret) {
          ENVOY_LOG(debug,
                    "AuthenticationFilter: the source ip is {}, the source "
                    "port is {}",
                    user, port);
        } else {
          ENVOY_LOG(error,
                    "AuthenticationFilter: GetSourceIpPort() returns false!");
        }
      }
    } else {
      ENVOY_LOG(
          debug,
          "AuthenticationFilter: {} this connection does not require mTLS",
          __func__);
    }
  }

  int origins_size = 0;
  // In POC, only inspect the first credential_rule
  if (config_.credential_rules_size() > 0 &&
      config_.credential_rules()[0].origins_size() > 0) {
    origins_size = config_.credential_rules()[0].origins_size();
  }
  ENVOY_LOG(debug, "AuthenticationFilter: {} config.origins_size()={}",
            __func__, origins_size);

  int num_config = 0;
  if (jwt_store_.find(IstioAuthn::ORIGIN_STORE) == jwt_store_.end()) {
    ENVOY_LOG(debug, "AuthenticationFilter: {} no ORIGIN_STORE", __func__);
    ENVOY_LOG(debug, "{}: the address of jwt_store is {:p}", __FUNCTION__,
              static_cast<void*>(&jwt_store_));
  } else if (jwt_store_[IstioAuthn::ORIGIN_STORE].size() == 0) {
    ENVOY_LOG(debug, "AuthenticationFilter: {} ORIGIN_STORE has size 0",
              __func__);
  }

  if (jwt_store_.find(IstioAuthn::ORIGIN_STORE) != jwt_store_.end() &&
      jwt_store_[IstioAuthn::ORIGIN_STORE].size() > 0) {
    num_config = jwt_store_[IstioAuthn::ORIGIN_STORE].size();
  }
  ENVOY_LOG(debug, "AuthenticationFilter: {} num_config is {}", __func__,
            num_config);

  if (num_config > 0) {
    const ::istio::authentication::v1alpha1::OriginAuthenticationMethod& m =
        config_.credential_rules()[0].origins()[0];
    const ::istio::authentication::v1alpha1::Jwt& jwt = m.jwt();
    ENVOY_LOG(debug,
              "AuthenticationFilter: {}: jwt.issuer()={}, jwt.jwks_uri()={}",
              __func__, jwt.issuer(), jwt.jwks_uri());
    state_ = Calling;
    stopped_ = false;

    Http::JwtAuth::JwtAuthStore& jwt_auth_store =
        jwt_store_[IstioAuthn::ORIGIN_STORE][0].store();
    jwt_auth_.reset(new Http::JwtAuth::JwtAuthenticator(cm_, jwt_auth_store));

    // Verify the JWT token, onDone() will be called when completed.
    jwt_auth_->Verify(headers, this);

    if (state_ == Complete) {
      return FilterHeadersStatus::Continue;
    }
    stopped_ = true;
    return FilterHeadersStatus::StopIteration;
  }
  ENVOY_LOG(
      debug,
      "Called AuthenticationFilter : {}, return FilterHeadersStatus::Continue;",
      __func__);
  return FilterHeadersStatus::Continue;
}

FilterDataStatus AuthenticationFilter::decodeData(Buffer::Instance&, bool) {
  ENVOY_LOG(debug, "Called AuthenticationFilter : {}", __func__);
  if (state_ == Calling) {
    ENVOY_LOG(debug,
              "Called AuthenticationFilter : {} "
              "FilterDataStatus::StopIterationAndBuffer;",
              __FUNCTION__);
    return FilterDataStatus::StopIterationAndBuffer;
  }
  ENVOY_LOG(debug,
            "Called AuthenticationFilter : {} FilterDataStatus::Continue;",
            __FUNCTION__);
  return FilterDataStatus::Continue;
}

FilterTrailersStatus AuthenticationFilter::decodeTrailers(HeaderMap&) {
  ENVOY_LOG(debug, "Called AuthenticationFilter: {}", __func__);
  if (state_ == Calling) {
    return FilterTrailersStatus::StopIteration;
  }
  return FilterTrailersStatus::Continue;
}

void AuthenticationFilter::setDecoderFilterCallbacks(
    StreamDecoderFilterCallbacks& callbacks) {
  ENVOY_LOG(debug, "Called AuthenticationFilter : {}", __func__);
  decoder_callbacks_ = &callbacks;
}

void AuthenticationFilter::onDone(const JwtAuth::Status& status) {
  ENVOY_LOG(debug, "Called AuthenticationFilter: check complete {}",
            int(status));
  // This stream has been reset, abort the callback.
  if (state_ == Responded) {
    return;
  }
  if (status != JwtAuth::Status::OK) {
    state_ = Responded;
    // JWT verification failed
    Code code = Code(401);  // Unauthorized
    // return failure reason as message body
    Utility::sendLocalReply(*decoder_callbacks_, false, code,
                            JwtAuth::StatusToString(status));
    return;
  }

  state_ = Complete;
  if (stopped_) {
    decoder_callbacks_->continueDecoding();
  }
}

}  // namespace Http
}  // namespace Envoy
