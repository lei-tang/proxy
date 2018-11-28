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

#include "src/envoy/http/jwt_auth/jwt_authenticator.h"
#include "common/http/message_impl.h"
#include "common/http/utility.h"

namespace Envoy {
namespace Http {
namespace JwtAuth {
namespace {

// The HTTP header to pass verified token payload.
const LowerCaseString kJwtPayloadKey("sec-istio-auth-userinfo");

// Extract host and path from a URI
void ExtractUriHostPath(const std::string& uri, std::string* host,
                        std::string* path) {
  // Example:
  // uri  = "https://example.com/certs"
  // pos  :          ^
  // pos1 :                     ^
  // host = "example.com"
  // path = "/certs"
  auto pos = uri.find("://");
  pos = pos == std::string::npos ? 0 : pos + 3;  // Start position of host
  auto pos1 = uri.find("/", pos);
  if (pos1 == std::string::npos) {
    // If uri doesn't have "/", the whole string is treated as host.
    *host = uri.substr(pos);
    *path = "/";
  } else {
    *host = uri.substr(pos, pos1 - pos);
    *path = "/" + uri.substr(pos1 + 1);
  }
}

}  // namespace

JwtAuthenticator::JwtAuthenticator(Upstream::ClusterManager& cm,
                                   JwtAuthStore& store)
    : cm_(cm), store_(store) {}

// Verify a JWT token.
void JwtAuthenticator::Verify(HeaderMap& headers,
                              JwtAuthenticator::Callbacks* callback) {
  headers_ = &headers;
  callback_ = callback;

  ENVOY_LOG(debug, "Jwt authentication starts");
  std::vector<std::unique_ptr<JwtTokenExtractor::Token>> tokens;
  store_.token_extractor().Extract(headers, &tokens);
  if (tokens.size() == 0) {
    if (OkToBypass()) {
      DoneWithStatus(Status::OK);
    } else {
      DoneWithStatus(Status::JWT_MISSED);
    }
    return;
  }

  // Only take the first one now.
  token_.swap(tokens[0]);

  jwt_.reset(new Jwt(token_->token()));
  if (jwt_->GetStatus() != Status::OK) {
    DoneWithStatus(jwt_->GetStatus());
    return;
  }

  // Check "exp" claim.
  const auto unix_timestamp =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();
  if (jwt_->Exp() < unix_timestamp) {
    DoneWithStatus(Status::JWT_EXPIRED);
    return;
  }

  // Check if token is extracted from the location specified by the issuer.
  if (!token_->IsIssuerAllowed(jwt_->Iss())) {
    ENVOY_LOG(debug, "Token for issuer {} did not specify extract location",
              jwt_->Iss());
    DoneWithStatus(Status::JWT_UNKNOWN_ISSUER);
    return;
  }

  // Check the issuer is configured or not.
  auto issuer = store_.pubkey_cache().LookupByIssuer(jwt_->Iss());
  if (!issuer) {
    DoneWithStatus(Status::JWT_UNKNOWN_ISSUER);
    return;
  }

  // Check if audience is allowed
  if (!issuer->IsAudienceAllowed(jwt_->Aud())) {
    DoneWithStatus(Status::AUDIENCE_NOT_ALLOWED);
    return;
  }

  if (issuer->pubkey() && !issuer->Expired()) {
    VerifyKey(*issuer);
    return;
  }

  FetchPubkey(issuer);
}

void JwtAuthenticator::FetchPubkey(PubkeyCacheItem* issuer) {
  uri_ = issuer->jwt_config().remote_jwks().http_uri().uri();
  std::string host, path;
  ExtractUriHostPath(uri_, &host, &path);

  MessagePtr message(new RequestMessageImpl());
  message->headers().insertMethod().value().setReference(
      Http::Headers::get().MethodValues.Get);
  message->headers().insertPath().value(path);
  message->headers().insertHost().value(host);

  const auto& cluster = issuer->jwt_config().remote_jwks().http_uri().cluster();
  if (cm_.get(cluster) == nullptr) {
    DoneWithStatus(Status::FAILED_FETCH_PUBKEY);
    return;
  }

  ENVOY_LOG(debug, "fetch pubkey from [uri = {}]: start", uri_);
  request_ = cm_.httpAsyncClientForCluster(cluster).send(
      std::move(message), *this, absl::optional<std::chrono::milliseconds>());
}

void JwtAuthenticator::onSuccess(MessagePtr&& response) {
  request_ = nullptr;
  uint64_t status_code = Http::Utility::getResponseStatus(response->headers());
  if (status_code == 200) {
    ENVOY_LOG(debug, "fetch pubkey [uri = {}]: success", uri_);
    std::string body;
    if (response->body()) {
      auto len = response->body()->length();
      body = std::string(static_cast<char*>(response->body()->linearize(len)),
                         len);
    } else {
      ENVOY_LOG(debug, "fetch pubkey [uri = {}]: body is empty", uri_);
    }
    OnFetchPubkeyDone(body);
  } else {
    ENVOY_LOG(debug, "fetch pubkey [uri = {}]: response status code {}", uri_,
              status_code);
    DoneWithStatus(Status::FAILED_FETCH_PUBKEY);
  }
}

void JwtAuthenticator::onFailure(AsyncClient::FailureReason) {
  request_ = nullptr;
  ENVOY_LOG(debug, "fetch pubkey [uri = {}]: failed", uri_);
  DoneWithStatus(Status::FAILED_FETCH_PUBKEY);
}

void JwtAuthenticator::onDestroy() {
  if (request_) {
    request_->cancel();
    request_ = nullptr;
    ENVOY_LOG(debug, "fetch pubkey [uri = {}]: canceled", uri_);
  }
}

// Handle the public key fetch done event.
void JwtAuthenticator::OnFetchPubkeyDone(const std::string& pubkey) {
  auto issuer = store_.pubkey_cache().LookupByIssuer(jwt_->Iss());
  Status status = issuer->SetRemoteJwks(pubkey);
  if (status != Status::OK) {
    DoneWithStatus(status);
  } else {
    VerifyKey(*issuer);
  }
}

// Verify with a specific public key.
void JwtAuthenticator::VerifyKey(const PubkeyCacheItem& issuer_item) {
  JwtAuth::Verifier v;
  if (!v.Verify(*jwt_, *issuer_item.pubkey())) {
    DoneWithStatus(v.GetStatus());
    return;
  }

  // Check whether there are distributed claims in the payload
  // The claim key for the distributed claims (OIDC Connect Core 1.0,
  // section 5.6.2). For example,
  //  "_claim_names": {
  //    "groups": "group_source_1"
  //  },
  //  "_claim_sources": {
  //    "group_source_1": {
  //      "endpoint": "https://127.0.0.1:63725/groups",
  //      "access_token": "group_access_token"
  //    }
  //  },
  std::string dist_claim_key;
  std::string dist_claim_val;
  std::string dist_claim_endpoint;
  std::string dist_claim_access_token;
  bool ret = ExtractDistributedClaimKeyValue(dist_claim_key, dist_claim_val);
  // Fetch the distributed claim endpoint and the access token.
  if (ret && !dist_claim_key.empty() && !dist_claim_val.empty()) {
    ENVOY_LOG(debug, "JWT contain a distributed claim ({}), with value ({})",
              dist_claim_key, dist_claim_val);
    ret = ExtractDistributedClaimEndpoint(dist_claim_val, dist_claim_endpoint,
                                          dist_claim_access_token);
    if (ret && !dist_claim_endpoint.empty() &&
        !dist_claim_access_token.empty()) {
      ENVOY_LOG(debug,
                "Distributed claim endpoint ({}), with access token ({})",
                dist_claim_endpoint, dist_claim_access_token);
      GetDistributedClaim(dist_claim_endpoint, dist_claim_access_token);
    }
  } else {
    ENVOY_LOG(debug, "No distributed claim extracted.");
  }

  // TODO: can we save as proto or json object directly?
  // User the issuer as the entry key for simplicity. The forward_payload_header
  // field can be removed or replace by a boolean (to make `save` is
  // conditional)
  callback_->savePayload(issuer_item.jwt_config().issuer(), jwt_->PayloadStr());

  if (!issuer_item.jwt_config().forward()) {
    // Remove JWT from headers.
    token_->Remove(headers_);
  }

  DoneWithStatus(Status::OK);
}

bool JwtAuthenticator::OkToBypass() {
  if (store_.config().allow_missing_or_failed()) {
    return true;
  }

  // TODO: use bypass field
  return false;
}

void JwtAuthenticator::DoneWithStatus(const Status& status) {
  ENVOY_LOG(debug, "Jwt authentication completed with: {}",
            JwtAuth::StatusToString(status));
  ENVOY_LOG(debug,
            "The value of allow_missing_or_failed in AuthFilterConfig is: {}",
            store_.config().allow_missing_or_failed());

  if (store_.config().allow_missing_or_failed()) {
    callback_->onDone(JwtAuth::Status::OK);
  } else {
    callback_->onDone(status);
  }
  callback_ = nullptr;
}

const LowerCaseString& JwtAuthenticator::JwtPayloadKey() {
  return kJwtPayloadKey;
}

bool JwtAuthenticator::ExtractDistributedClaimKeyValue(std::string& key,
                                                       std::string& val) {
  // The claim key for the distributed claims (OIDC Connect Core 1.0,
  // section 5.6.2).
  std::string claim_names_key = "_claim_names";
  Envoy::Json::ObjectSharedPtr claim_obj;
  try {
    if (!jwt_->Payload()->hasObject(claim_names_key)) {
      ENVOY_LOG(debug, "The JWT does not contain a distributed claim.");
      return false;
    }
    claim_obj = jwt_->Payload()->getObject(claim_names_key);
    if (!claim_obj) {
      return false;
    }
  } catch (Json::Exception& e) {
    ENVOY_LOG(debug, "{}: unable to get the claim object", __FUNCTION__);
    return false;
  }

  ENVOY_LOG(debug, "{}: distributed claim object is {}", __FUNCTION__,
            claim_obj->asJsonString());
  std::map<std::string, std::string> claims;
  // Extract claims as strings
  claim_obj->iterate([claim_obj, &claims](const std::string& key,
                                          const Json::Object&) -> bool {
    // In current implementation, only string claims are extracted
    try {
      // Try as string, will throw execption if object type is not string.
      std::string claim_val = claim_obj->getString(key);
      ENVOY_LOG(debug, "Distributed claim {} is extracted", key);
      claims[key] = claim_val;
    } catch (Json::Exception& e) {
      // Not convertable to string
      ENVOY_LOG(debug, "{}: distributed claim {} is NOT string", __FUNCTION__,
                key);
    }
    return true;
  });
  // Only process one distributed claim
  if (!claims.empty()) {
    key = claims.begin()->first;
    val = claims.begin()->second;
    return true;
  }
  return false;
}

bool JwtAuthenticator::ExtractDistributedClaimEndpoint(
    const std::string& source, std::string& endpoint, std::string& token) {
  // The claim key for the distributed claims (OIDC Connect Core 1.0,
  // section 5.6.2).
  std::string claim_key = "_claim_sources";
  std::string endpoint_key = "endpoint";
  std::string access_token_key = "access_token";

  Envoy::Json::ObjectSharedPtr claim_obj;
  try {
    if (!jwt_->Payload()->hasObject(claim_key)) {
      ENVOY_LOG(debug, "The JWT does not contain a distributed claim source.");
      return false;
    }
    claim_obj = jwt_->Payload()->getObject(claim_key);
    if (!claim_obj) {
      return false;
    }
  } catch (Json::Exception& e) {
    ENVOY_LOG(debug, "{}: unable to get the claim source object", __FUNCTION__);
    return false;
  }

  ENVOY_LOG(debug, "{}: distributed claim source object is {}", __FUNCTION__,
            claim_obj->asJsonString());

  Envoy::Json::ObjectSharedPtr source_obj;
  try {
    if (!claim_obj->hasObject(source)) {
      ENVOY_LOG(
          debug,
          "The source object does not contain the distributed claim source {}.",
          source);
      return false;
    }
    source_obj = claim_obj->getObject(source);
    if (!source_obj) {
      return false;
    }
  } catch (Json::Exception& e) {
    ENVOY_LOG(debug, "{}: unable to get the claim source object", __FUNCTION__);
    return false;
  }

  std::map<std::string, std::string> claims;
  // Extract claims in the distributed source as strings
  source_obj->iterate([source_obj, &claims](const std::string& key,
                                            const Json::Object&) -> bool {
    // In current implementation, only string claims are extracted
    try {
      // Try as string, will throw execption if object type is not string.
      std::string claim_val = source_obj->getString(key);
      ENVOY_LOG(debug, "Distributed source claim {} is extracted", key);
      claims[key] = claim_val;
    } catch (Json::Exception& e) {
      // Not convertable to string
      ENVOY_LOG(debug, "{}: distributed source claim {} is NOT string",
                __FUNCTION__, key);
    }
    return true;
  });
  if (!claims.empty() && claims.count(endpoint_key) > 0 &&
      claims.count(access_token_key) > 0) {
    endpoint = claims[endpoint_key];
    token = claims[access_token_key];
    return true;
  }
  return false;
}

void JwtAuthenticator::GetDistributedClaim(const std::string endpoint,
                                           const std::string token) {
  ENVOY_LOG(debug, "Get the distributed claim from ({}), token ({})", endpoint,
            token);
  std::string cluster;
  for (const auto u : store_.config().dist_uri_whitelist()) {
    ENVOY_LOG(debug, "Whitelisted URI: uri ({}), cluster ({})", u.uri(),
              u.cluster());
    if (endpoint == u.uri()) {
      cluster = u.cluster();
      ENVOY_LOG(debug, "The endpoint ({}) has the cluster ({})", endpoint,
                cluster);
      break;
    }
  }
  if (cluster.empty()) {
    return;
  }
}

}  // namespace JwtAuth
}  // namespace Http
}  // namespace Envoy
