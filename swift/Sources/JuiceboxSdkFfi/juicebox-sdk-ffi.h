#ifndef JUICEBOX_FFI_H_
#define JUICEBOX_FFI_H_

/* This file was automatically generated by cbindgen */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Error returned during `Client.delete`
 */
typedef enum {
  /**
   * A realm rejected the `Client`'s auth token.
   */
  JuiceboxDeleteErrorInvalidAuth = 0,
  /**
   * A software error has occurred. This request should not be retried
   * with the same parameters. Verify your inputs, check for software
   * updates and try again.
   */
  JuiceboxDeleteErrorAssertion = 1,
  /**
   * A transient error in sending or receiving requests to a realm.
   * This request may succeed by trying again with the same parameters.
   */
  JuiceboxDeleteErrorTransient = 2,
} JuiceboxDeleteError;

typedef enum {
  JuiceboxHttpRequestMethodGet = 0,
  JuiceboxHttpRequestMethodPut,
  JuiceboxHttpRequestMethodPost,
  JuiceboxHttpRequestMethodDelete,
} JuiceboxHttpRequestMethod;

typedef enum {
  /**
   * A tuned hash, secure for use on modern devices as of 2019 with low-entropy PINs.
   */
  JuiceboxPinHashingModeStandard2019 = 0,
  /**
   * A fast hash used for testing. Do not use in production.
   */
  JuiceboxPinHashingModeFastInsecure = 1,
} JuiceboxPinHashingMode;

/**
 * Error returned during `Client.recover`
 */
typedef enum {
  /**
   * The secret could not be unlocked, but you can try again
   * with a different PIN if you have guesses remaining. If no
   * guesses remain, this secret is locked and inaccessible.
   */
  JuiceboxRecoverErrorReasonInvalidPin = 0,
  /**
   * The secret was not registered or not fully registered with the
   * provided realms.
   */
  JuiceboxRecoverErrorReasonNotRegistered = 1,
  /**
   * A realm rejected the `Client`'s auth token.
   */
  JuiceboxRecoverErrorReasonInvalidAuth = 2,
  /**
   * A software error has occurred. This request should not be retried
   * with the same parameters. Verify your inputs, check for software
   * updates and try again.
   */
  JuiceboxRecoverErrorReasonAssertion = 3,
  /**
   * A transient error in sending or receiving requests to a realm.
   * This request may succeed by trying again with the same parameters.
   */
  JuiceboxRecoverErrorReasonTransient = 4,
} JuiceboxRecoverErrorReason;

/**
 * Error returned during `Client.register`
 */
typedef enum {
  /**
   * A realm rejected the `Client`'s auth token.
   */
  JuiceboxRegisterErrorInvalidAuth = 0,
  /**
   * A software error has occurred. This request should not be retried
   * with the same parameters. Verify your inputs, check for software
   * updates and try again.
   */
  JuiceboxRegisterErrorAssertion = 1,
  /**
   * A transient error in sending or receiving requests to a realm.
   * This request may succeed by trying again with the same parameters.
   */
  JuiceboxRegisterErrorTransient = 2,
} JuiceboxRegisterError;

typedef struct JuiceboxAuthTokenManager JuiceboxAuthTokenManager;

typedef struct JuiceboxClient JuiceboxClient;

typedef struct JuiceboxConfiguration JuiceboxConfiguration;

typedef struct JuiceboxHttpClient JuiceboxHttpClient;

typedef struct {
  JuiceboxConfiguration *const *data;
  size_t length;
} JuiceboxUnmanagedConfigurationArray;

typedef void (*JuiceboxAuthTokenGetCallbackFn)(JuiceboxAuthTokenManager *context, uint64_t context_id, const char *auth_token);

typedef void (*JuiceboxAuthTokenGetFn)(const JuiceboxAuthTokenManager *context, uint64_t context_id, const uint8_t (*realm_id)[16], JuiceboxAuthTokenGetCallbackFn callback);

typedef struct {
  const char *name;
  const char *value;
} JuiceboxHttpHeader;

typedef struct {
  const JuiceboxHttpHeader *data;
  size_t length;
} JuiceboxUnmanagedHttpHeaderArray;

typedef struct {
  const uint8_t *data;
  size_t length;
} JuiceboxUnmanagedDataArray;

typedef struct {
  uint8_t id[16];
  JuiceboxHttpRequestMethod method;
  const char *url;
  JuiceboxUnmanagedHttpHeaderArray headers;
  JuiceboxUnmanagedDataArray body;
} JuiceboxHttpRequest;

typedef struct {
  uint8_t id[16];
  uint16_t status_code;
  JuiceboxUnmanagedHttpHeaderArray headers;
  JuiceboxUnmanagedDataArray body;
} JuiceboxHttpResponse;

typedef void (*JuiceboxHttpResponseFn)(JuiceboxHttpClient *context, const JuiceboxHttpResponse *response);

typedef void (*JuiceboxHttpSendFn)(const JuiceboxHttpClient *context, const JuiceboxHttpRequest *request, JuiceboxHttpResponseFn callback);

typedef struct {
  uint8_t id[16];
  const char *address;
  const JuiceboxUnmanagedDataArray *public_key;
} JuiceboxRealm;

typedef struct {
  const JuiceboxRealm *data;
  size_t length;
} JuiceboxUnmanagedRealmArray;

typedef struct {
  JuiceboxRecoverErrorReason reason;
  /**
   * If non-NULL, the number of guesses remaining after an Unsuccessful attempt.
   */
  const uint16_t *guesses_remaining;
} JuiceboxRecoverError;

/**
 * Constructs a new opaque `JuiceboxClient`.
 *
 * # Arguments
 *
 * * `configuration` – Represents the current configuration. The configuration
 * provided must include at least one `JuiceboxRealm`.
 * * `previous_configurations` – Represents any other configurations you have
 * previously registered with that you may not yet have migrated the data from.
 * During `juicebox_client_recover`, they will be tried if the current user has not yet
 * registered on the current configuration. These should be ordered from most recently
 * to least recently used.
 * * `auth_token` – Represents the authority to act as a particular user
 * and should be valid for the lifetime of the `JuiceboxClient`.
 * * `http_send` – A function pointer `http_send` that will be called when the client
 * wishes to make a network request. The appropriate request should be executed by you,
 * and the the response provided to the response function pointer. This send
 * should be performed asynchronously. `http_send` should not block on
 * performing the request, and the response should be returned to the
 * `response` function pointer argument when the asynchronous work has
 * completed. The request parameter is only valid for the lifetime of the
 * `http_send` function and should not be accessed after returning from the
 * function.
 */
JuiceboxClient *juicebox_client_create(JuiceboxConfiguration *configuration,
                                       JuiceboxUnmanagedConfigurationArray previous_configurations,
                                       JuiceboxAuthTokenGetFn auth_token_get,
                                       JuiceboxHttpSendFn http_send);

void juicebox_client_destroy(JuiceboxClient *client);

const char *juicebox_sdk_version(void);

JuiceboxConfiguration *juicebox_configuration_create(JuiceboxUnmanagedRealmArray realms,
                                                     uint32_t register_threshold,
                                                     uint32_t recover_threshold,
                                                     JuiceboxPinHashingMode pin_hashing_mode);

JuiceboxConfiguration *juicebox_configuration_create_from_json(const char *json);

void juicebox_configuration_destroy(JuiceboxConfiguration *configuration);

bool juicebox_configurations_are_equal(JuiceboxConfiguration *configuration1,
                                       JuiceboxConfiguration *configuration2);

/**
 * Stores a new PIN-protected secret on the configured realms.
 *
 * # Note
 *
 * The provided secret must have a maximum length of 128-bytes.
 */
void juicebox_client_register(JuiceboxClient *client,
                              const void *context,
                              JuiceboxUnmanagedDataArray pin,
                              JuiceboxUnmanagedDataArray secret,
                              JuiceboxUnmanagedDataArray info,
                              uint16_t num_guesses,
                              void (*response)(const void *context, const JuiceboxRegisterError *error));

/**
 * Retrieves a PIN-protected secret from the configured realms, or falls
 * back to the previous realms if the current realms do not have a secret
 * registered.
 */
void juicebox_client_recover(JuiceboxClient *client,
                             const void *context,
                             JuiceboxUnmanagedDataArray pin,
                             JuiceboxUnmanagedDataArray info,
                             void (*response)(const void *context, JuiceboxUnmanagedDataArray secret, const JuiceboxRecoverError *error));

/**
 * Deletes the registered secret for this user, if any.
 */
void juicebox_client_delete(JuiceboxClient *client,
                            const void *context,
                            void (*response)(const void *context, const JuiceboxDeleteError *error));

#endif /* JUICEBOX_FFI_H_ */
