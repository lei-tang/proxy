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

#include "src/envoy/IAP_auth/authentication_http_filter.h"
#include "src/envoy/IAP_auth/authentication_store.h"

#include "common/http/message_impl.h"
#include "common/http/utility.h"
#include "envoy/http/async_client.h"
#include "server/config/network/http_connection_manager.h"
#include "src/envoy/IAP_auth/policy.pb.validate.h"

#include <chrono>
#include <string>

namespace Envoy {
namespace Http {

AuthenticationFilter::AuthenticationFilter(Upstream::ClusterManager& cm,
                                           Auth::AuthenticationStore& store)
        :cm_(cm),store_(store) {}

AuthenticationFilter::~AuthenticationFilter() {}

void AuthenticationFilter::onDestroy() {
  ENVOY_LOG(debug, "Called AuthenticationFilter : {}", __func__);
  // jwt_auth_.onDestroy();
}

FilterHeadersStatus AuthenticationFilter::decodeHeaders(HeaderMap&, bool) {
  ENVOY_LOG(debug, "Called AuthenticationFilter : {}", __func__);
  state_ = Calling;
  stopped_ = false;

  const ::istio::authentication::v1alpha1::Policy& config= store_.config();
  int peer_size = config.peers().size();
  ENVOY_LOG(debug, "AuthenticationFilter: {} config.peers().size()={}",
            __func__, peer_size);
  for(int i=0; i<peer_size; i++) {
    const ::istio::authentication::v1alpha1::Mechanism &m= config.peers()[i];
    if(m.has_mtls()) {
      ENVOY_LOG(debug, "AuthenticationFilter: {} this connection requires mTLS",
                __func__);
    }else {
      ENVOY_LOG(debug, "AuthenticationFilter: {} this connection does not require mTLS",
                __func__);
    }
  }

  // Verify the JWT token, onDone() will be called when completed.
  // jwt_auth_.Verify(headers, this);
  // Skip jwt validattion, simply say OK
  onDone(Auth::Status::OK);

  if (state_ == Complete) {
    ENVOY_LOG(debug, "Called AuthenticationFilter : {}, return FilterHeadersStatus::Continue;",
              __func__);
    return FilterHeadersStatus::Continue;
  }
  ENVOY_LOG(debug, "Called AuthenticationFilter : {} Stop", __func__);
  stopped_ = true;
  return FilterHeadersStatus::StopIteration;
}

void AuthenticationFilter::onDone(const Auth::Status& status) {
  ENVOY_LOG(debug, "Called AuthenticationFilter : check complete {}",
            int(status));
  // This stream has been reset, abort the callback.
  if (state_ == Responded) {
    return;
  }
  if (status != Auth::Status::OK) {
    state_ = Responded;
    // verification failed
    Code code = Code(401);  // Unauthorized
    // return failure reason as message body
    Utility::sendLocalReply(*decoder_callbacks_, false, code,
                            Auth::StatusToString(status));
    return;
  }

  state_ = Complete;
  if (stopped_) {
    ENVOY_LOG(debug, "Called AuthenticationFilter : {} call decoder_callbacks_->continueDecoding();",
              __FUNCTION__);
    decoder_callbacks_->continueDecoding();
  }
}

FilterDataStatus AuthenticationFilter::decodeData(Buffer::Instance&, bool) {
  ENVOY_LOG(debug, "Called AuthenticationFilter : {}", __func__);
  if (state_ == Calling) {
    ENVOY_LOG(debug, "Called AuthenticationFilter : {} return FilterDataStatus::StopIterationAndBuffer;",
                        __FUNCTION__);
    return FilterDataStatus::StopIterationAndBuffer;
  }
  ENVOY_LOG(debug, "Called AuthenticationFilter : {} FilterDataStatus::Continue;",
            __FUNCTION__);
  return FilterDataStatus::Continue;
}

FilterTrailersStatus AuthenticationFilter::decodeTrailers(HeaderMap&) {
  ENVOY_LOG(debug, "Called AuthenticationFilter : {}", __func__);
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

}  // Http
}  // Envoy
