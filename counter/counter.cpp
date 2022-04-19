// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/app_interface.h"
#include "formatters.h"
#include "logging_schema.h"
#include "node/quote.h"
#include "node/rpc/metrics_tracker.h"
#include "node/rpc/user_frontend.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#define KEY_SIZE 2048
#define EXPONENT 65537

using namespace std;
using namespace nlohmann;

namespace loggingapp
{
  // SNIPPET: table_definition
  using Table = kv::Map<size_t, string>;

  // SNIPPET_START: custom_identity
  struct CustomIdentity : public ccf::AuthnIdentity
  {
    std::string name;
    size_t age;
  };
  // SNIPPET_END: custom_identity

  // SNIPPET_START: custom_auth_policy
  class CustomAuthPolicy : public ccf::AuthnPolicy
  {
  public:
    std::unique_ptr<ccf::AuthnIdentity> authenticate(
      kv::ReadOnlyTx&,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto& headers = ctx->get_request_headers();

      constexpr auto name_header_key = "x-custom-auth-name";
      const auto name_header_it = headers.find(name_header_key);
      if (name_header_it == headers.end())
      {
        error_reason =
          fmt::format("Missing required header {}", name_header_key);
        return nullptr;
      }

      const auto& name = name_header_it->second;
      if (name.empty())
      {
        error_reason = "Name must not be empty";
        return nullptr;
      }

      constexpr auto age_header_key = "x-custom-auth-age";
      const auto age_header_it = headers.find(age_header_key);
      if (name_header_it == headers.end())
      {
        error_reason =
          fmt::format("Missing required header {}", age_header_key);
        return nullptr;
      }

      const auto& age_s = age_header_it->second;
      size_t age;
      const auto [p, ec] =
        std::from_chars(age_s.data(), age_s.data() + age_s.size(), age);
      if (ec != std::errc())
      {
        error_reason =
          fmt::format("Unable to parse age header as a number: {}", age_s);
        return nullptr;
      }

      constexpr auto min_age = 16;
      if (age < min_age)
      {
        error_reason = fmt::format("Caller age must be at least {}", min_age);
        return nullptr;
      }

      auto ident = std::make_unique<CustomIdentity>();
      ident->name = name;
      ident->age = age;
      return ident;
    }

    std::optional<ccf::OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      // There is no OpenAPI-compliant way to describe this auth scheme, so we
      // return nullopt
      return std::nullopt;
    }
  };
  // SNIPPET_END: custom_auth_policy

  // SNIPPET: inherit_frontend
  class LoggerHandlers : public ccf::UserEndpointRegistry
  {
  private:
    Table records;
    Table public_records;

    const nlohmann::json record_public_params_schema;
    const nlohmann::json record_public_result_schema;

    const nlohmann::json get_public_params_schema;
    const nlohmann::json get_public_result_schema;

    metrics::Tracker metrics_tracker;

  public:
    // SNIPPET_START: constructor
    LoggerHandlers(
      ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(nwt),
      records("records"),
      public_records("public:records"),
      // SNIPPET_END: constructor
      record_public_params_schema(nlohmann::json::parse(j_record_public_in)),
      record_public_result_schema(nlohmann::json::parse(j_record_public_out)),
      get_public_params_schema(nlohmann::json::parse(j_get_public_in)),
      get_public_result_schema(nlohmann::json::parse(j_get_public_out))
    {
      const ccf::endpoints::AuthnPolicies user_cert_required = {ccf::user_cert_auth_policy};

      // SNIPPET_START: [init] Generate Public-Private Key for Signature Generation
      auto init = [this](kv::Tx& tx) {
        
        size_t pri_len = 2048;
        size_t pub_len = 2048;
        unsigned char *pri_key;
        unsigned char *pub_key;
        pri_key = (unsigned char*) malloc(pri_len + 1);
        pub_key = (unsigned char*) malloc(pub_len + 1);     
        const char *pers = "rsa_genkey";
        
        mbedtls_pk_context pk;    
        mbedtls_rsa_context rsa;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
        
        mbedtls_ctr_drbg_init( &ctr_drbg );
        mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
        mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
        mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
        mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );
        mbedtls_entropy_init( &entropy );
        
        int ret = 1;
        char err_msg[512];
        
        if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
          mbedtls_rsa_free( &rsa );
          mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
          mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
          mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
          sprintf(err_msg, "[init] failed! mbedtls_rsa_check_privkey returned -0x%0x\n", (unsigned int) -ret);
          std::string err_str(err_msg);
          return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }
        
        if((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT)) != 0) {
          mbedtls_rsa_free( &rsa );
          mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
          mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
          mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
          sprintf(err_msg, "[init] failed! mbedtls_rsa_gen_key returned -0x%0x\n", (unsigned int) -ret);
          std::string err_str(err_msg);
          return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }

        if((ret = mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E)) != 0 || (ret = mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP)) != 0 ) {
          mbedtls_rsa_free( &rsa );
          mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
          mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
          mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
          sprintf(err_msg, "[init] failed! mbedtls_rsa_export returned -0x%0x\n", (unsigned int) -ret);
          std::string err_str(err_msg);
          return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }

        if((ret = mbedtls_rsa_complete(&rsa)) != 0) {
          mbedtls_rsa_free( &rsa );
          mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
          mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
          mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
          sprintf(err_msg, "[init] failed! mbedtls_rsa_complete returned -0x%0x\n", (unsigned int) -ret);
          std::string err_str(err_msg);
          return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }

        mbedtls_pk_init( &pk );

        if((ret = mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA) )) != 0) {
          mbedtls_rsa_free( &rsa );
          mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
          mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
          mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
          mbedtls_entropy_free( &entropy );
          sprintf(err_msg, "[init] failed! mbedtls_pk_setup returned -0x%0x\n", (unsigned int) -ret);
          std::string err_str(err_msg);
          return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }
        
        memcpy(mbedtls_pk_rsa(pk),  &rsa, sizeof(mbedtls_rsa_context));

        if((ret = mbedtls_pk_write_key_pem( &pk, pri_key, pri_len )) != 0) {
          mbedtls_rsa_free( &rsa );
          mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
          mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
          mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
          mbedtls_entropy_free( &entropy );
          sprintf(err_msg, "[init] failed! mbedtls_pk_write_key_pem returned -0x%0x\n", (unsigned int) -ret);
          std::string err_str(err_msg);
          return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }
        
        if((ret = mbedtls_pk_write_pubkey_pem ( &pk, pub_key, pub_len )) != 0) {
          mbedtls_rsa_free( &rsa );
          mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
          mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
          mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
          mbedtls_entropy_free( &entropy );
          sprintf(err_msg, "[init] failed! mbedtls_pk_write_pubkey_pem returned -0x%0x\n", (unsigned int) -ret);
          std::string err_str(err_msg);
          return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }
        
        mbedtls_rsa_free( &rsa );
        mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
        mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
        mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
        
        auto view = tx.get_view(records);
        string temp = "3";
        view->put(0, temp);
        string prikey = (char*)pri_key;
        view->put(1, prikey);
        string pubkey = (char*)pub_key; 
        view->put(2, pubkey);
        json result;
        result["status"] = "true";
        return ccf::make_success(result);
        
      };
      // SNIPPET_END: [init]
      
      // SNIPPET_START: install_init
      make_endpoint("counter/init", HTTP_POST, ccf::json_adapter(init), user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: install_init
        
        
      // SNIPPET_START: [reset] Generate new counter initialized to 0, return counter_id
      auto reset = [this](kv::Tx& tx) {
        
        auto view = tx.get_view(records);
        auto r = view->get(0);
        int index = std::stoi(r.value());
        json result;
        result["counter_id"] = index;
        string initial = "0";
        view->put(index, initial);
        index++;
        view->put(0, std::to_string(index));
        return ccf::make_success(result);
        
      };
      // SNIPPET_END: [reset]
      
      // SNIPPET_START: install_reset
      make_endpoint("counter/reset", HTTP_POST, ccf::json_adapter(reset), user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: install_reset
              
        
      // SNIPPET_START: [increment] Increment counter at counter_id and return {signature,new_counter}
      auto increment = [this](kv::Tx& tx, nlohmann::json&& params) {
        
        auto view = tx.get_view(records);
        const auto counter_id = params["id"].get<std::string>();
        char *input_id = (char *) malloc(256 + 1);  
        strcpy(input_id, counter_id.c_str());
        int index = atoi(counter_id.c_str());
        auto r = view->get(index);
        int counter_value = std::stoi(r.value());
        counter_value++;
        char count_str[64];
        sprintf(count_str, "%d", counter_value);
        
        const auto hash = params["hash"].get<std::string>();
        char *input_hash = (char*) malloc(256 + 1);  
        strcpy(input_hash, hash.c_str());
        strcat(input_hash, count_str);
        
        size_t pri_len = 2048;
        const char *f = (char*) malloc(pri_len + 1);     
        auto pri = view->get(1);        
        f = pri.value().c_str();

        int ret = 1;
        char err_msg[200];
        unsigned char hashbuf[32];
        unsigned char buf[MBEDTLS_MPI_MAX_SIZE];  
        
        mbedtls_rsa_context rsa;
        mbedtls_pk_context pk;
        mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
        
        mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
        mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
        mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
        mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );
        mbedtls_pk_init(&pk);
        
        if((ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)f, strlen(f)+1, 0, 0)) != 0) {
            mbedtls_rsa_free( &rsa );
            mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
            mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
            mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
            sprintf(err_msg, "[increment] failed! mbedtls_pk_parse_key returned -0x%0x\n", (unsigned int) -ret);
            std::string err_str(err_msg);
            return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }

        mbedtls_rsa_context *rsapk = mbedtls_pk_rsa( pk );
            
        if((ret = mbedtls_rsa_check_privkey(rsapk)) != 0) {
            mbedtls_rsa_free( &rsa );
            mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
            mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
            mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
            sprintf(err_msg, "[increment] failed! mbedtls_rsa_check_privkey returned -0x%0x\n", (unsigned int) -ret);
            std::string err_str(err_msg);
            return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }

        if((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)input_hash, strlen((const char *)input_hash), hashbuf)) != 0) {
            mbedtls_rsa_free( &rsa );
            mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
            mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
            mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
            sprintf(err_msg, "[increment] failed! mbedtls_md returned -0x%0x\n", (unsigned int) -ret);
            std::string err_str(err_msg);
            return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }

        if((ret = mbedtls_rsa_pkcs1_sign(rsapk, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 64, hashbuf, buf)) != 0) {
            mbedtls_rsa_free( &rsa );
            mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
            mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
            mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
            sprintf(err_msg, "[increment] failed! mbedtls_rsa_pkcs1_sign returned -0x%0x\n", (unsigned int) -ret);
            std::string err_str(err_msg);
            return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }
        
        mbedtls_rsa_free( &rsa );
        mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
        mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
        mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

        unsigned char buf_enc[4096];
        size_t olen;
        if((ret = mbedtls_base64_encode((unsigned char *)buf_enc, 4096, &olen, (const unsigned char *)buf, 256)) != 0) {
            sprintf(err_msg, "[increment] failed! mbedtls_base64_encode returned -0x%0x\n", (unsigned int) -ret);
            std::string err_str(err_msg);
            return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }
        
        std::string signature((char*)buf_enc);
        view->put(index, std::to_string(counter_value));
        json result;
        result["value"] = counter_value;
        result["signature"] = signature;
        return ccf::make_success(result);
        
      };
      // SNIPPET_END: [increment]

      // SNIPPET_START: install_increment
      make_endpoint("counter/increment", HTTP_POST, ccf::json_adapter(increment), user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: install_increment      

        
      // SNIPPET_START: [sign_counter] Get counter at counter_id and return {signature,counter}
      auto sign_counter = [this](kv::Tx& tx, nlohmann::json&& params) {
        
        auto view = tx.get_view(records);
        const auto counter_id = params["id"].get<std::string>();
        char *input_id = (char *) malloc(256 + 1);  
        strcpy(input_id, counter_id.c_str());
        int index = atoi(counter_id.c_str());
        auto r = view->get(index);
        int counter_value = std::stoi(r.value());
        char count_str[64];
        sprintf(count_str, "%d", counter_value);
        
        const auto hash = params["hash"].get<std::string>();
        char *input_hash = (char*) malloc(256 + 1);  
        strcpy(input_hash, hash.c_str());
        strcat(input_hash, count_str);
        
        size_t pri_len = 2048;
        const char *f = (char*) malloc(pri_len + 1);     
        auto pri = view->get(1);        
        f = pri.value().c_str();

        int ret = 1;
        char err_msg[200];
        unsigned char hashbuf[32];
        unsigned char buf[MBEDTLS_MPI_MAX_SIZE];  
        
        mbedtls_rsa_context rsa;
        mbedtls_pk_context pk;
        mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
        
        mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
        mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
        mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
        mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );
        mbedtls_pk_init(&pk);
        
        if((ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)f, strlen(f)+1, 0, 0)) != 0) {
            mbedtls_rsa_free( &rsa );
            mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
            mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
            mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
            sprintf(err_msg, "[increment] failed! mbedtls_pk_parse_key returned -0x%0x\n", (unsigned int) -ret);
            std::string err_str(err_msg);
            return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }

        mbedtls_rsa_context *rsapk = mbedtls_pk_rsa( pk );
            
        if((ret = mbedtls_rsa_check_privkey(rsapk)) != 0) {
            mbedtls_rsa_free( &rsa );
            mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
            mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
            mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
            sprintf(err_msg, "[increment] failed! mbedtls_rsa_check_privkey returned -0x%0x\n", (unsigned int) -ret);
            std::string err_str(err_msg);
            return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }

        if((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)input_hash, strlen((const char *)input_hash), hashbuf)) != 0) {
            mbedtls_rsa_free( &rsa );
            mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
            mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
            mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
            sprintf(err_msg, "[increment] failed! mbedtls_md returned -0x%0x\n", (unsigned int) -ret);
            std::string err_str(err_msg);
            return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }

        if((ret = mbedtls_rsa_pkcs1_sign(rsapk, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 64, hashbuf, buf)) != 0) {
            mbedtls_rsa_free( &rsa );
            mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
            mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
            mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
            sprintf(err_msg, "[increment] failed! mbedtls_rsa_pkcs1_sign returned -0x%0x\n", (unsigned int) -ret);
            std::string err_str(err_msg);
            return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }
        
        mbedtls_rsa_free( &rsa );
        mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
        mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
        mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

        unsigned char buf_enc[4096];
        size_t olen;
        if((ret = mbedtls_base64_encode((unsigned char *)buf_enc, 4096, &olen, (const unsigned char *)buf, 256)) != 0) {
            sprintf(err_msg, "[increment] failed! mbedtls_base64_encode returned -0x%0x\n", (unsigned int) -ret);
            std::string err_str(err_msg);
            return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidInput, err_str);
        }
        
        std::string signature((char*)buf_enc);
        view->put(index, std::to_string(counter_value));
        json result;
        result["value"] = counter_value;
        result["signature"] = signature;
        return ccf::make_success(result);
        
      };
      // SNIPPET_END: [sign_counter]

      // SNIPPET_START: sign_counter
      make_endpoint("counter/sign_counter", HTTP_POST, ccf::json_adapter(sign_counter), user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: sign_counter   
        
        
      // SNIPPET_START: [value]
      auto value = [this](ccf::ReadOnlyEndpointContext& args, nlohmann::json&& params) {
        
          auto view = args.tx.get_read_only_view(records);
          const auto counter_id = params["id"].get<std::string>();
          int index = atoi(counter_id.c_str());
          auto r = view->get(index);
        
          if (r.has_value()) {
            json result;
            result["value"] = r.value();
            return ccf::make_success(result);
          }
        
          return ccf::make_error(HTTP_STATUS_BAD_REQUEST, ccf::errors::ResourceNotFound, fmt::format("No such record: {}.", index));
        
      };
      // SNIPPET_END: [value]

      // SNIPPET_START: install_value
      make_read_only_endpoint("counter/value", HTTP_GET, ccf::json_read_only_adapter(value), user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: install_value
          
 
      // SNIPPET_START: record
      auto record = [this](kv::Tx& tx, nlohmann::json&& params) {
        // SNIPPET_START: macro_validation_record
        const auto in = params.get<LoggingRecord::In>();
        // SNIPPET_END: macro_validation_record

        if (in.msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message.");
        }

        auto view = tx.get_view(records);
        view->put(in.id, in.msg);
        return ccf::make_success(true);
      };
      // SNIPPET_END: record

      // SNIPPET_START: install_record
      make_endpoint(
        "log/private", HTTP_POST, ccf::json_adapter(record), user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: install_record

      make_endpoint(
        "log/private",
        ws::Verb::WEBSOCKET,
        ccf::json_adapter(record),
        user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      // SNIPPET_START: get
      auto get =
        [this](ccf::ReadOnlyEndpointContext& args, nlohmann::json&& params) {
          const auto in = params.get<LoggingGet::In>();
          auto view = args.tx.get_read_only_view(records);
          auto r = view->get(in.id);

          if (r.has_value())
            return ccf::make_success(LoggingGet::Out{r.value()});

          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ResourceNotFound,
            fmt::format("No such record: {}.", in.id));
        };
      // SNIPPET_END: get

      // SNIPPET_START: install_get
      make_read_only_endpoint(
        "log/private",
        HTTP_GET,
        ccf::json_read_only_adapter(get),
        user_cert_required)
        .set_auto_schema<LoggingGet>()
        .install();
      // SNIPPET_END: install_get

      auto remove = [this](kv::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRemove::In>();
        auto view = tx.get_view(records);
        auto removed = view->remove(in.id);

        return ccf::make_success(LoggingRemove::Out{removed});
      };
      make_endpoint(
        "log/private",
        HTTP_DELETE,
        ccf::json_adapter(remove),
        user_cert_required)
        .set_auto_schema<LoggingRemove>()
        .install();

      // SNIPPET_START: record_public
      auto record_public = [this](kv::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRecord::In>();

        if (in.msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message.");
        }

        auto view = tx.get_view(public_records);
        view->put(params["id"], in.msg);
        return ccf::make_success(true);
      };
      // SNIPPET_END: record_public
      make_endpoint(
        "log/public",
        HTTP_POST,
        ccf::json_adapter(record_public),
        user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      // SNIPPET_START: get_public
      auto get_public =
        [this](ccf::ReadOnlyEndpointContext& args, nlohmann::json&& params) {
          const auto in = params.get<LoggingGet::In>();
          auto view = args.tx.get_read_only_view(public_records);
          auto r = view->get(in.id);

          if (r.has_value())
            return ccf::make_success(LoggingGet::Out{r.value()});

          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ResourceNotFound,
            fmt::format("No such record: {}.", in.id));
        };
      // SNIPPET_END: get_public
      make_read_only_endpoint(
        "log/public",
        HTTP_GET,
        ccf::json_read_only_adapter(get_public),
        user_cert_required)
        .set_auto_schema<LoggingGet>()
        .install();

      auto remove_public = [this](kv::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRemove::In>();
        auto view = tx.get_view(public_records);
        auto removed = view->remove(in.id);

        return ccf::make_success(LoggingRemove::Out{removed});
      };
      make_endpoint(
        "log/public",
        HTTP_DELETE,
        ccf::json_adapter(remove_public),
        user_cert_required)
        .set_auto_schema<LoggingRemove>()
        .install();

      // SNIPPET_START: log_record_prefix_cert
      auto log_record_prefix_cert = [this](ccf::EndpointContext& args) {
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());

        const auto in = body_j.get<LoggingRecord::In>();
        if (in.msg.empty())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body("Cannot record an empty log message");
          return;
        }

        auto cert = mbedtls::make_unique<mbedtls::X509Crt>();

        const auto& cert_data = args.rpc_ctx->session->caller_cert;
        const auto ret = mbedtls_x509_crt_parse(
          cert.get(), cert_data.data(), cert_data.size());
        if (ret != 0)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(
            "Cannot parse x509 caller certificate");
          return;
        }

        const auto log_line = fmt::format("{}: {}", cert->subject, in.msg);
        auto view = args.tx.get_view(records);
        view->put(in.id, log_line);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        args.rpc_ctx->set_response_body(nlohmann::json(true).dump());
      };
      make_endpoint(
        "log/private/prefix_cert",
        HTTP_POST,
        log_record_prefix_cert,
        user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: log_record_prefix_cert

      auto log_record_anonymous =
        [this](ccf::EndpointContext& args, nlohmann::json&& params) {
          const auto in = params.get<LoggingRecord::In>();
          if (in.msg.empty())
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidInput,
              "Cannot record an empty log message.");
          }

          const auto log_line = fmt::format("Anonymous: {}", in.msg);
          auto view = args.tx.get_view(records);
          view->put(in.id, log_line);
          return ccf::make_success(true);
        };
      make_endpoint(
        "log/private/anonymous",
        HTTP_POST,
        ccf::json_adapter(log_record_anonymous),
        ccf::no_auth_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      auto multi_auth = [](auto& ctx) {
        if (
          auto user_cert_ident =
            ctx.template try_get_caller<ccf::UserCertAuthnIdentity>())
        {
          auto response = std::string("User TLS cert");
          response += fmt::format(
            "\nThe caller is a user with ID: {}", user_cert_ident->user_id);
          response += fmt::format(
            "\nThe caller's user data is: {}",
            user_cert_ident->user_data.dump());
          response += fmt::format(
            "\nThe caller's cert is:\n{}", user_cert_ident->user_cert.str());

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        else if (
          auto member_cert_ident =
            ctx.template try_get_caller<ccf::MemberCertAuthnIdentity>())
        {
          auto response = std::string("Member TLS cert");
          response += fmt::format(
            "\nThe caller is a member with ID: {}",
            member_cert_ident->member_id);
          response += fmt::format(
            "\nThe caller's member data is: {}",
            member_cert_ident->member_data.dump());
          response += fmt::format(
            "\nThe caller's cert is:\n{}",
            member_cert_ident->member_cert.str());

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        else if (
          auto user_sig_ident =
            ctx.template try_get_caller<ccf::UserSignatureAuthnIdentity>())
        {
          auto response = std::string("User HTTP signature");
          response += fmt::format(
            "\nThe caller is a user with ID: {}", user_sig_ident->user_id);
          response += fmt::format(
            "\nThe caller's user data is: {}",
            user_sig_ident->user_data.dump());
          response += fmt::format(
            "\nThe caller's cert is:\n{}", user_sig_ident->user_cert.str());

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        else if (
          auto member_sig_ident =
            ctx.template try_get_caller<ccf::MemberSignatureAuthnIdentity>())
        {
          auto response = std::string("Member HTTP signature");
          response += fmt::format(
            "\nThe caller is a member with ID: {}",
            member_sig_ident->member_id);
          response += fmt::format(
            "\nThe caller's member data is: {}",
            member_sig_ident->member_data.dump());
          response += fmt::format(
            "\nThe caller's cert is:\n{}", member_sig_ident->member_cert.str());

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        else if (
          auto jwt_ident = ctx.template try_get_caller<ccf::JwtAuthnIdentity>())
        {
          auto response = std::string("JWT");
          response += fmt::format(
            "\nThe caller is identified by a JWT issued by: {}",
            jwt_ident->key_issuer);
          response +=
            fmt::format("\nThe JWT header is:\n{}", jwt_ident->header.dump(2));
          response += fmt::format(
            "\nThe JWT payload is:\n{}", jwt_ident->payload.dump(2));

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        else if (
          auto no_ident =
            ctx.template try_get_caller<ccf::EmptyAuthnIdentity>())
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body("Unauthenticated");
          return;
        }
        else
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          ctx.rpc_ctx->set_response_body("Unhandled auth type");
          return;
        }
      };
      make_endpoint(
        "multi_auth",
        HTTP_GET,
        multi_auth,
        {ccf::user_cert_auth_policy,
         ccf::user_signature_auth_policy,
         ccf::member_cert_auth_policy,
         ccf::member_signature_auth_policy,
         ccf::jwt_auth_policy,
         ccf::empty_auth_policy})
        .set_auto_schema<void, std::string>()
        .install();

      // SNIPPET_START: custom_auth_endpoint
      auto custom_auth = [](auto& ctx) {
        const auto& caller_identity = ctx.template get_caller<CustomIdentity>();
        nlohmann::json response;
        response["name"] = caller_identity.name;
        response["age"] = caller_identity.age;
        response["description"] = fmt::format(
          "Your name is {} and you are {}",
          caller_identity.name,
          caller_identity.age);
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_body(response.dump(2));
      };
      auto custom_policy = std::make_shared<CustomAuthPolicy>();
      make_endpoint("custom_auth", HTTP_GET, custom_auth, {custom_policy})
        .set_auto_schema<void, nlohmann::json>()
        .install();
      // SNIPPET_END: custom_auth_endpoint

      // SNIPPET_START: log_record_text
      auto log_record_text = [this](auto& args) {
        const auto expected = http::headervalues::contenttype::TEXT;
        const auto actual =
          args.rpc_ctx->get_request_header(http::headers::CONTENT_TYPE)
            .value_or("");
        if (expected != actual)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(fmt::format(
            "Expected content-type '{}'. Got '{}'.", expected, actual));
          return;
        }

        const auto& path_params = args.rpc_ctx->get_request_path_params();
        const auto id_it = path_params.find("id");
        if (id_it == path_params.end())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(
            fmt::format("Missing ID component in request path"));
          return;
        }

        const auto id = strtoul(id_it->second.c_str(), nullptr, 10);

        const std::vector<uint8_t>& content = args.rpc_ctx->get_request_body();
        const std::string log_line(content.begin(), content.end());

        auto view = args.tx.get_view(records);
        view->put(id, log_line);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      };
      make_endpoint(
        "log/private/raw_text/{id}",
        HTTP_POST,
        log_record_text,
        user_cert_required)
        .install();
      // SNIPPET_END: log_record_text

      auto get_historical = [this](
                              ccf::EndpointContext& args,
                              ccf::historical::StorePtr historical_store,
                              kv::Consensus::View,
                              kv::Consensus::SeqNo) {
        const auto [pack, params] =
          ccf::jsonhandler::get_json_params(args.rpc_ctx);

        const auto in = params.get<LoggingGetHistorical::In>();

        auto historical_tx = historical_store->create_read_only_tx();
        auto view = historical_tx.get_read_only_view(records);
        const auto v = view->get(in.id);

        if (v.has_value())
        {
          LoggingGetHistorical::Out out;
          out.msg = v.value();
          nlohmann::json j = out;
          ccf::jsonhandler::set_response(std::move(j), args.rpc_ctx, pack);
        }
        else
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
        }
      };

      auto is_tx_committed = [this](
                               kv::Consensus::View view,
                               kv::Consensus::SeqNo seqno,
                               std::string& error_reason) {
        if (consensus == nullptr)
        {
          error_reason = "Node is not fully configured";
          return false;
        }

        const auto tx_view = consensus->get_view(seqno);
        const auto committed_seqno = consensus->get_committed_seqno();
        const auto committed_view = consensus->get_view(committed_seqno);

        const auto tx_status = ccf::get_tx_status(
          view, seqno, tx_view, committed_view, committed_seqno);
        if (tx_status != ccf::TxStatus::Committed)
        {
          error_reason = fmt::format(
            "Only committed transactions can be queried. Transaction {}.{} is "
            "{}",
            view,
            seqno,
            ccf::tx_status_to_str(tx_status));
          return false;
        }

        return true;
      };
      make_endpoint(
        "log/private/historical",
        HTTP_GET,
        ccf::historical::adapter(
          get_historical, context.get_historical_state(), is_tx_committed),
        user_cert_required)
        .set_auto_schema<LoggingGetHistorical>()
        .set_forwarding_required(ccf::ForwardingRequired::Never)
        .install();

      auto record_admin_only =
        [this, &nwt](ccf::EndpointContext& ctx, nlohmann::json&& params) {
          {
            const auto& caller_ident =
              ctx.get_caller<ccf::UserCertAuthnIdentity>();

            // SNIPPET_START: user_data_check
            // Check caller's user-data for required permissions
            auto users_view = ctx.tx.get_view(nwt.users);
            const auto user_opt = users_view->get(caller_ident.user_id);
            const nlohmann::json user_data = user_opt.has_value() ?
              user_opt->user_data :
              nlohmann::json(nullptr);
            const auto is_admin_it = user_data.find("isAdmin");

            // Exit if this user has no user data, or the user data is not an
            // object with isAdmin field, or the value of this field is not true
            if (
              !user_data.is_object() || is_admin_it == user_data.end() ||
              !is_admin_it.value().get<bool>())
            {
              return ccf::make_error(
                HTTP_STATUS_FORBIDDEN,
                ccf::errors::AuthorizationFailed,
                "Only admins may access this endpoint.");
            }
            // SNIPPET_END: user_data_check
          }

          const auto in = params.get<LoggingRecord::In>();

          if (in.msg.empty())
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidInput,
              "Cannot record an empty log message.");
          }

          auto view = ctx.tx.get_view(records);
          view->put(in.id, in.msg);
          return ccf::make_success(true);
        };
      make_endpoint(
        "log/private/admin_only",
        HTTP_POST,
        ccf::json_adapter(record_admin_only),
        user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      metrics_tracker.install_endpoint(*this);
    }

    void tick(
      std::chrono::milliseconds elapsed,
      kv::Consensus::Statistics stats) override
    {
      metrics_tracker.tick(elapsed, stats);

      ccf::UserEndpointRegistry::tick(elapsed, stats);
    }
  };

  class Logger : public ccf::UserRpcFrontend
  {
  private:
    LoggerHandlers logger_handlers;

  public:
    Logger(ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context) :
      ccf::UserRpcFrontend(*network.tables, logger_handlers),
      logger_handlers(network, context)
    {}

    void open(std::optional<tls::Pem*> identity = std::nullopt) override
    {
      ccf::UserRpcFrontend::open(identity);
      logger_handlers.openapi_info.title = "CCF Sample Logging App";
      logger_handlers.openapi_info.description =
        "This CCF sample app implements a simple logging application, securely "
        "recording messages at client-specified IDs. It demonstrates most of "
        "the features available to CCF apps.";
    }
  };
}

namespace ccfapp
{
  // SNIPPET_START: rpc_handler
  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context)
  {
    return make_shared<loggingapp::Logger>(nwt, context);
  }
  // SNIPPET_END: rpc_handler
}
