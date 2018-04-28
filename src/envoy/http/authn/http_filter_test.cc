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
#include "common/common/base64.h"
#include "common/http/header_map_impl.h"
#include "envoy/config/filter/http/authn/v2alpha1/config.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "src/envoy/http/authn/authenticator_base.h"
#include "src/envoy/http/authn/test_utils.h"
#include "src/envoy/utils/authn.h"
#include "test/mocks/http/mocks.h"
#include "test/test_common/utility.h"

using Envoy::Http::Istio::AuthN::AuthenticatorBase;
using Envoy::Http::Istio::AuthN::FilterContext;
using istio::authn::Payload;
using istio::authn::Result;
using istio::envoy::config::filter::http::authn::v2alpha1::FilterConfig;
using testing::Invoke;
using testing::NiceMock;
using testing::StrictMock;
using testing::_;

namespace iaapi = istio::authentication::v1alpha1;

namespace Envoy {
namespace Http {
namespace Istio {
namespace AuthN {
namespace {

const char ingorePolicy[] = R"(
  peer_is_optional: false
  origin_is_optional: false
  principal_binding: USE_ORIGIN
  origins {
    jwt {
      issuer: "abc.xyz"
    }
  }
)";


// Create a fake authenticator for test. This authenticator do nothing except
// making the authentication fail.
std::unique_ptr<AuthenticatorBase> createAlwaysFailAuthenticator(
    FilterContext* filter_context) {
  class _local : public AuthenticatorBase {
   public:
    _local(FilterContext* filter_context) : AuthenticatorBase(filter_context) {}
    bool run(Payload*) override { return false; }
  };
  return std::make_unique<_local>(filter_context);
}

// Create a fake authenticator for test. This authenticator do nothing except
// making the authentication successful.
std::unique_ptr<AuthenticatorBase> createAlwaysPassAuthenticator(
    FilterContext* filter_context) {
  class _local : public AuthenticatorBase {
   public:
    _local(FilterContext* filter_context) : AuthenticatorBase(filter_context) {}
    bool run(Payload*) override {
      // Set some data to verify authentication result later.
      auto payload = TestUtilities::CreateX509Payload("foo");
      filter_context()->setPeerResult(&payload);
      return true;
    }
  };
  return std::make_unique<_local>(filter_context);
}

class MockAuthenticationFilter : public AuthenticationFilter {
 public:
  // We'll use fake authenticator for test, so policy is not really needed. Use
  // default config for simplicity.
  /*
  MockAuthenticationFilter()
      : AuthenticationFilter(FilterConfig::default_instance()) {}*/

  MockAuthenticationFilter(const FilterConfig& filter_config)
      : AuthenticationFilter(filter_config) {
    std::cout<<"*************MockAuthenticationFilter constructor\n";
  }

  ~MockAuthenticationFilter(){
    std::cout<<"*******MockAuthenticationFilter destructor\n";
  };

  MOCK_METHOD1(createPeerAuthenticator,
               std::unique_ptr<AuthenticatorBase>(FilterContext*));
  MOCK_METHOD1(createOriginAuthenticator,
               std::unique_ptr<AuthenticatorBase>(FilterContext*));
};

class AuthenticationFilterTest : public testing::Test {
 public:
  AuthenticationFilterTest()
      : request_headers_{{":method", "GET"}, {":path", "/"}} {
  }
  ~AuthenticationFilterTest() {
    std::cout<<"*******AuthenticationFilterTest destructor\n";
    //filter_config_ = nullptr;
  }

  void SetUp() override {
    std::cout<<"*************AuthenticationFilterTest setup\n";
    filter_.setDecoderFilterCallbacks(decoder_callbacks_);
  }

  void TearDown() override {
    std::cout<<"*************AuthenticationFilterTest TearDown\n";
  }

 protected:
  FilterConfig filter_config_;
  iaapi::Policy policy_;

  StrictMock<MockAuthenticationFilter> filter_{filter_config_};
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks_;
  Http::TestHeaderMapImpl request_headers_;
};

/*
TEST_F(AuthenticationFilterTest, PeerFail) {
  // Peer authentication fail, request should be rejected with 401. No origin
  // authentiation needed.
  ASSERT_TRUE(Protobuf::TextFormat::ParseFromString(ingorePolicy, &policy_));
  filter_config_.set_allocated_policy(&policy_);

  EXPECT_CALL(filter_, createPeerAuthenticator(_))
      .Times(1)
      .WillOnce(Invoke(createAlwaysFailAuthenticator));
  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(_, _))
      .Times(1)
      .WillOnce(testing::Invoke([](Http::HeaderMap& headers, bool) {
        EXPECT_STREQ("401", headers.Status()->value().c_str());
      }));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration,
            filter_.decodeHeaders(request_headers_, true));
  EXPECT_FALSE(Utils::Authentication::HasResultInHeader(request_headers_));
}*/

TEST_F(AuthenticationFilterTest, PeerPassOrginFail) {
  // Peer pass thus origin authentication must be called. Final result should
  // fail as origin authn fails.

  ASSERT_TRUE(Protobuf::TextFormat::ParseFromString(ingorePolicy, &policy_));
  filter_config_.set_allocated_policy(&policy_);
  //MockAuthenticationFilter* filter_ = new StrictMock<MockAuthenticationFilter>(filter_config_);
  //filter_->setDecoderFilterCallbacks(decoder_callbacks_);

  std::cout<<"*************AuthenticationFilterTest policy {}\n" << policy_.DebugString();

  EXPECT_CALL(filter_, createPeerAuthenticator(_))
      .Times(1)
      .WillOnce(Invoke(createAlwaysPassAuthenticator));

  std::cout<<"*************createPeerAuthenticator done\n";

  EXPECT_CALL(filter_, createOriginAuthenticator(_))
      .Times(1)
      .WillOnce(Invoke(createAlwaysFailAuthenticator));

  std::cout<<"*************createOriginAuthenticator done\n"; 

  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(_, _))
      .Times(1)
      .WillOnce(testing::Invoke([](Http::HeaderMap& headers, bool) {
        EXPECT_STREQ("401", headers.Status()->value().c_str());
      }));

  std::cout<<"*************after EXPECT_CALL\n";

  //EXPECT_EQ(Http::FilterHeadersStatus::StopIteration,
  //          filter_.decodeHeaders(request_headers_, true));

  ASSERT_EQ(Http::FilterHeadersStatus::StopIteration, filter_.decodeHeaders(request_headers_, true));



  //FilterHeadersStatus status = filter_.decodeHeaders(request_headers_, true);
  //ASSERT_EQ(Http::FilterHeadersStatus::StopIteration, status);
  //std::cout << static_cast<std::underlying_type<FilterHeadersStatus>::type>(status) << std::endl;

  EXPECT_FALSE(Utils::Authentication::HasResultInHeader(request_headers_));

  std::cout<<"*************test case finish\n";
}


/*
TEST_F(AuthenticationFilterTest, AllPass) {
  EXPECT_CALL(filter_, createPeerAuthenticator(_))
      .Times(1)
      .WillOnce(Invoke(createAlwaysPassAuthenticator));
  EXPECT_CALL(filter_, createOriginAuthenticator(_))
      .Times(1)
      .WillOnce(Invoke(createAlwaysPassAuthenticator));
  EXPECT_EQ(Http::FilterHeadersStatus::Continue,
            filter_.decodeHeaders(request_headers_, true));
  Result authn;
  EXPECT_TRUE(
      Utils::Authentication::FetchResultFromHeader(request_headers_, &authn));
  EXPECT_TRUE(TestUtility::protoEqual(
      TestUtilities::AuthNResultFromString(R"(peer_user: "foo")"), authn));
}

TEST_F(AuthenticationFilterTest, IngorePeerOrginFail) {
  EXPECT_CALL(filter_, createPeerAuthenticator(_))
      .Times(1)
      .WillOnce(Invoke(createAlwaysFailAuthenticator));
  EXPECT_CALL(filter_, createOriginAuthenticator(_))
      .Times(1)
      .WillOnce(Invoke(createAlwaysFailAuthenticator));

  FilterHeadersStatus status = filter_.decodeHeaders(request_headers_, true);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue,
            status);

  std::cout<<"*************IngorePeerOrginFail status\n";
  std::cout << static_cast<std::underlying_type<FilterHeadersStatus>::type>(status) << std::endl;

  Result authn;
  EXPECT_TRUE(
      Utils::Authentication::FetchResultFromHeader(request_headers_, &authn));
  EXPECT_TRUE(TestUtility::protoEqual(
      TestUtilities::AuthNResultFromString(R"(peer_user: "foo")"), authn));
} */

}  // namespace
}  // namespace AuthN
}  // namespace Istio
}  // namespace Http
}  // namespace Envoy
