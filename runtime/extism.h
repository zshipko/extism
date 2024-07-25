#pragma once

#include <stdint.h>
#include <stdbool.h>

#define EXTISM_FUNCTION(N) extern void N(ExtismCurrentPlugin*, const ExtismVal*, ExtismSize, ExtismVal*, ExtismSize, void*)
#define EXTISM_GO_FUNCTION(N) extern void N(void*, ExtismVal*, ExtismSize, ExtismVal*, ExtismSize, uintptr_t)

/** The return code from extism_plugin_call used to signal a successful call with no errors */
#define EXTISM_SUCCESS 0

/** An alias for I64 to signify an Extism handle */
#define EXTISM_HANDLE ExtismValType_I64


typedef enum {
  I32,
  I64,
  F32,
  F64,
  ExternRef,
} ExtismValType;

typedef struct ExtismCancelHandle ExtismCancelHandle;

typedef struct ExtismCurrentPlugin ExtismCurrentPlugin;

typedef struct ExtismFunction ExtismFunction;

typedef struct ExtismPlugin ExtismPlugin;

typedef uint32_t ExtismSize;

typedef uint64_t ExtismMemoryHandle;

/**
 * The return code used to specify a successful plugin call
 * A union type for host function argument/return values
 */
typedef union {
  int32_t i32;
  int64_t i64;
  float f32;
  double f64;
  void *externref;
} ExtismValUnion;

/**
 * `ExtismVal` holds the type and value of a function argument/return
 */
typedef struct {
  ExtismValType t;
  ExtismValUnion v;
} ExtismVal;

/**
 * Host function signature
 */
typedef void (*ExtismFunctionType)(ExtismCurrentPlugin *plugin,
                                   const ExtismVal *inputs,
                                   ExtismSize n_inputs,
                                   ExtismVal *outputs,
                                   ExtismSize n_outputs,
                                   void *data);

/**
 * Log drain callback
 */
typedef void (*ExtismLogDrainFunctionType)(const char *data, ExtismSize size);



#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Get a plugin's ID, the returned bytes are a 16 byte buffer that represent a UUIDv4
 */
const uint8_t *extism_plugin_id(ExtismPlugin *plugin);

/**
 * Returns a pointer to the memory of the currently running plugin
 * NOTE: this should only be called from host functions.
 */
uint8_t *extism_current_plugin_memory(ExtismCurrentPlugin *plugin);

/**
 * Get the length of an Extism handle
 * NOTE: this should only be called from host functions.
 */
ExtismSize extism_current_plugin_memory_length(ExtismCurrentPlugin *plugin, ExtismMemoryHandle n);

/**
 * Create a new host function
 *
 * Arguments
 * - `module_name`: this should be valid UTF-8
 * - `name`: function name, this should be valid UTF-8
 * - `inputs`: argument types
 * - `n_inputs`: number of argument types
 * - `outputs`: return types
 * - `n_outputs`: number of return types
 * - `func`: the function to call
 * - `user_data`: a pointer that will be passed to the function when it's called
 *    this value should live as long as the function exists
 * - `free_user_data`: a callback to release the `user_data` value when the resulting
 *   `ExtismFunction` is freed.
 *
 * Returns a new `ExtismFunction` or `null` if the `name` argument is invalid.
 */
ExtismFunction *extism_function_new(const char *module_name,
                                    const char *name,
                                    const ExtismValType *inputs,
                                    ExtismSize n_inputs,
                                    const ExtismValType *outputs,
                                    ExtismSize n_outputs,
                                    ExtismFunctionType func,
                                    void *user_data,
                                    void (*free_user_data)(void *_));

/**
 * Free `ExtismFunction`
 */
void extism_function_free(ExtismFunction *f);

/**
 * Create a new plugin with host functions, the functions passed to this function no longer need to be manually freed using
 *
 * `wasm`: is a WASM module (wat or wasm) or a JSON encoded manifest
 * `wasm_size`: the length of the `wasm` parameter
 * `functions`: an array of `ExtismFunction*`
 * `n_functions`: the number of functions provided
 * `with_wasi`: enables/disables WASI
 */
ExtismPlugin *extism_plugin_new(const uint8_t *wasm,
                                ExtismSize wasm_size,
                                const ExtismFunction **functions,
                                ExtismSize n_functions,
                                bool with_wasi,
                                char **errmsg);

/**
 * Free the error returned by `extism_plugin_new`, errors returned from `extism_plugin_error` don't need to be freed
 */
void extism_plugin_new_error_free(char *err);

/**
 * Remove a plugin from the registry and free associated memory
 */
void extism_plugin_free(ExtismPlugin *plugin);

/**
 * Get handle for plugin cancellation
 */
const ExtismCancelHandle *extism_plugin_cancel_handle(ExtismPlugin *plugin);

/**
 * Cancel a running plugin
 */
bool extism_plugin_cancel(const ExtismCancelHandle *handle);

bool extism_plugin_function_exists(ExtismPlugin *plugin, const char *func_name);

/**
 * Call a function
 *
 * `func_name`: is the function to call
 * `data`: is the input data
 * `data_len`: is the length of `data`
 */
const char *extism_plugin_call(ExtismPlugin *plugin,
                               const char *func_name,
                               const uint8_t *data,
                               ExtismSize data_len);

/**
 * Get the error associated with a `Plugin`
 */
const char *extism_plugin_error(ExtismPlugin *plugin);

ExtismSize extism_plugin_output_length(ExtismPlugin *plugin);

const uint8_t *extism_plugin_output_data(ExtismPlugin *plugin);

/**
 * Set log file and level.
 * The log level can be either one of: info, error, trace, debug, warn or a more
 * complex filter like `extism=trace,cranelift=debug`
 * The file will be created if it doesn't exist.
 */
bool extism_log_file(const char *filename, const char *log_level);

/**
 * Enable a custom log handler, this will buffer logs until `extism_log_drain` is called
 * Log level should be one of: info, error, trace, debug, warn
 */
bool extism_log_custom(const char *log_level);

/**
 * Calls the provided callback function for each buffered log line.
 * This is only needed when `extism_log_custom` is used.
 */
void extism_log_drain(ExtismLogDrainFunctionType handler);

/**
 * Get the Extism version string
 */
const char *extism_version(void);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
