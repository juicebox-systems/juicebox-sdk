#ifndef LOAM_FFI_H_
#define LOAM_FFI_H_

/* This file was automatically generated by cbindgen */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum {
  LoamDeleteErrorInvalidAuth = 0,
  LoamDeleteErrorNetwork = 1,
  LoamDeleteErrorProtocol = 2,
} LoamDeleteError;

typedef enum {
  LoamHttpRequestMethodGet = 0,
  LoamHttpRequestMethodPut,
  LoamHttpRequestMethodPost,
  LoamHttpRequestMethodDelete,
} LoamHttpRequestMethod;

typedef enum {
  LoamRecoverErrorInvalidAuth = 0,
  LoamRecoverErrorNetwork = 1,
  LoamRecoverErrorUnsuccessful = 2,
  LoamRecoverErrorProtocol = 3,
} LoamRecoverError;

typedef enum {
  LoamRegisterErrorInvalidAuth = 0,
  LoamRegisterErrorNetwork = 1,
  LoamRegisterErrorProtocol = 2,
  LoamRegisterErrorUnavailable = 3,
} LoamRegisterError;

/**
 * Used to register and recover PIN-protected secrets on behalf of a
 * particular user.
 */
typedef struct LoamClient LoamClient;

typedef struct LoamHttpClient LoamHttpClient;

typedef struct {
  const uint8_t *data;
  size_t length;
} LoamUnmanagedDataArray;

typedef struct {
  uint8_t id[16];
  const char *address;
  LoamUnmanagedDataArray public_key;
} LoamRealm;

typedef struct {
  const LoamRealm *data;
  size_t length;
} LoamUnmanagedRealmArray;

typedef struct {
  LoamUnmanagedRealmArray realms;
  uint8_t register_threshold;
  uint8_t recover_threshold;
} LoamConfiguration;

typedef struct {
  const char *name;
  const char *value;
} LoamHttpHeader;

typedef struct {
  const LoamHttpHeader *data;
  size_t length;
} LoamUnmanagedHttpHeaderArray;

typedef struct {
  uint8_t id[16];
  LoamHttpRequestMethod method;
  const char *url;
  LoamUnmanagedHttpHeaderArray headers;
  LoamUnmanagedDataArray body;
} LoamHttpRequest;

typedef struct {
  uint8_t id[16];
  uint16_t status_code;
  LoamUnmanagedHttpHeaderArray headers;
  LoamUnmanagedDataArray body;
} LoamHttpResponse;

typedef void (*LoamHttpResponseFn)(LoamHttpClient *context, const LoamHttpResponse *response);

typedef void (*LoamHttpSendFn)(const LoamHttpClient *context, const LoamHttpRequest *request, LoamHttpResponseFn callback);

/**
 * Creates a new opaque `LoamClient` reference.
 *
 * The configuration provided must include at least one realm.
 *
 * The `auth_token` represents the authority to act as a particular user and
 * should be valid for the lifetime of the `LoamClient`. It should be a
 * base64-encoded JWT.
 *
 * The function pointer `http_send` will be called when the client wishes to
 * make a network request. The appropriate request should be executed by you,
 * and the the response provided to the response function pointer. This send
 * should be performed asynchronously. `http_send` should not block on
 * performing the request, and the response should be returned to the
 * `response` function pointer argument when the asynchronous work has
 * completed. The request parameter is only valid for the lifetime of the
 * `http_send` function and should not be accessed after returning from the
 * function.
 */
LoamClient *loam_client_create(LoamConfiguration configuration,
                               const char *auth_token,
                               LoamHttpSendFn http_send);

void loam_client_destroy(LoamClient *client);

/**
 * Stores a new PIN-protected secret.
 *
 * If it's successful, this also deletes any prior secrets for this user.
 *
 * # Warning
 *
 * If the secrets vary in length (such as passwords), the caller should
 * add padding to obscure the secrets' length.
 */
void loam_client_register(LoamClient *client,
                          const void *context,
                          LoamUnmanagedDataArray pin,
                          LoamUnmanagedDataArray secret,
                          uint16_t num_guesses,
                          void (*response)(const void *context, const LoamRegisterError *error));

/**
 * Retrieves a PIN-protected secret.
 *
 * If it's successful, this also deletes any earlier secrets for this
 * user.
 */
void loam_client_recover(LoamClient *client,
                         const void *context,
                         LoamUnmanagedDataArray pin,
                         void (*response)(const void *context, LoamUnmanagedDataArray secret, const LoamRecoverError *error));

/**
 * Deletes all secrets for this user.
 *
 * Note: This does not delete the user's audit log.
 */
void loam_client_delete_all(LoamClient *client,
                            const void *context,
                            void (*response)(const void *context, const LoamDeleteError *error));

#endif /* LOAM_FFI_H_ */
