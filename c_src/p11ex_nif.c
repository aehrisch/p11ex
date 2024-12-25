#include <erl_nif.h>
#include <string.h>
#include <stdio.h>

#include <dlfcn.h>

#include "p11.h"

/* macros */

# define P11_DEBUG 1

#define P11_debug_msg(msg) \
  if (P11_DEBUG) { \
    printf("P11_debug_msg: %s\n", msg); \
  }

/* macro that checks if the number of arguments is correct */
#define REQUIRE_ARGS(env, argc, expected) \
    if (argc != expected) { \
        return enif_make_badarg(env); \
    }

/* macro that checks if the argument is an Erlang boolean, and if so, converts it to CK_BOOL. */
#define BOOL_ARG(env, term, bool_var) \
    if (!enif_is_atom(env, term)) { \
        return enif_make_badarg(env); \
    } \
    if (enif_compare(term, enif_make_atom(env, "true")) == 0) { \
        bool_var = CK_TRUE; \
    } \
    bool_var = CK_FALSE;

/* macro that checks if the argument is an Erlang number, and if so, converts it to CK_ULONG. */
#define ULONG_ARG(env, term, ulong_var) \
    if (!enif_is_number(env, term)) { \
      return enif_make_badarg(env); \
    } \
    enif_get_ulong(env, term, &ulong_var);

/* macro that wraps a CK_VERSION into a tuple */
#define wrap_version(env, v) \
    (enif_make_tuple2(env, enif_make_int(env, v.major), enif_make_int(env, v.minor)))

/* macro that creates an error tuple with the function name and the error code */
#define P11_error(env, fname, rv) \
    (enif_make_tuple2(env, \
      enif_make_atom(env, "error"), \
      enif_make_tuple2(env, enif_make_atom(env, fname), ckr_to_atom(env, rv))))

#define P11_call(rv, p11_module, func, args...) \
    if (P11_DEBUG) { \
        printf("P11_call: %s\n", #func); \
    } \
    rv = p11_module->fun_list->func(args); \
    if (P11_DEBUG) { \
        printf("P11_call: %s returned %lu\n", #func, rv); \
    }


/* struct that holds the PKCS#11 module and the function list */
typedef struct {
   void *p11_module;
   CK_FUNCTION_LIST_PTR fun_list;
} p11_module_t;

static ErlNifResourceType *p11_module_resource_type = NULL;

/* struct that holds the session handle */
typedef struct {
  CK_SESSION_HANDLE session_handle;
} p11_session_t;

static ErlNifResourceType *p11_session_resource_type = NULL;

void resource_cleanup(ErlNifEnv* env, void* obj) {
  /* TODO: Implement cleanup */
}

/* Forward declarations */
static ERL_NIF_TERM load_module(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM list_slots(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM token_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM open_session(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM close_session(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM session_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM session_login(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM session_logout(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM ckr_to_atom(ErlNifEnv* env, CK_RV rv);
static ERL_NIF_TERM to_elixir_string(ErlNifEnv* env, CK_UTF8CHAR_PTR utf8_array);

/* NIF function registration */
static ErlNifFunc nif_funcs[] = {
  {"n_load_module", 1, load_module},
  {"n_list_slots", 2, list_slots},
  {"n_token_info", 2, token_info},
  {"n_open_session", 3, open_session},
  {"n_close_session", 2, close_session},
  {"n_session_info", 2, session_info},
  {"n_session_login", 4, session_login},
  {"n_session_logout", 2, session_logout}
};

/* Implementation of load_module/1: Load a PKCS#11 module, get the function list, 
   and initialize the module. Returns a resource that holds a reference the module and. */
static ERL_NIF_TERM load_module(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    char path[1024];
    CK_RV rv;
    CK_C_GetFunctionList c_get_function_list;
    CK_FUNCTION_LIST_PTR fun_list;
    ERL_NIF_TERM error_str;

    P11_debug_msg("load_module: enter");

    p11_module_t* p11_module_rt = 
      enif_alloc_resource(p11_module_resource_type, sizeof(p11_module_t));
        
    if (argc != 1) {
      return enif_make_badarg(env);
    }

    rv = enif_get_string(env, argv[0], path, sizeof(path), ERL_NIF_UTF8);
    if (rv <= 0) {
      enif_release_resource(p11_module_rt);
      return enif_make_tuple2(env, 
        enif_make_atom(env, "error"),
        enif_make_atom(env, "invalid_path"));
    }

    /* load the PKCS#11 module */
    P11_debug_msg("load_module: dlopen");
    void *pkcs11_lib = dlopen(path, RTLD_NOW);
    
    if (!pkcs11_lib) {
      P11_debug_msg("load_module: dlopen failed");
      enif_release_resource(p11_module_rt);
      error_str = enif_make_string(env, dlerror(), ERL_NIF_UTF8);
      return enif_make_tuple3(env, 
        enif_make_atom(env, "error"),
        enif_make_atom(env, "dlopen_failed"),
        error_str);
    }

    /* C_GetFunctionList can be called before C_Initialize */
    P11_debug_msg("load_module: dlsym C_GetFunctionList");
    c_get_function_list = (CK_C_GetFunctionList) dlsym(pkcs11_lib, "C_GetFunctionList");
    if (!c_get_function_list) {
      char *error_cstr = dlerror();
      error_str = enif_make_string(env, error_cstr, ERL_NIF_UTF8);
      P11_debug_msg("load_module: dlsym C_GetFunctionList failed");
      P11_debug_msg(error_cstr);
      enif_release_resource(p11_module_rt);
      return enif_make_tuple3(env, 
        enif_make_atom(env, "error"),
        enif_make_atom(env, "dlsym_failed"),
        error_str);
    }

    /* Now, actually call C_GetFunctionList */
    P11_debug_msg("load_module: c_get_function_list");
    rv = c_get_function_list(&fun_list);
    if (rv != CKR_OK) {
      P11_debug_msg("load_module: c_get_function_list failed");
        enif_release_resource(p11_module_rt);
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_atom(env, "get_function_list_failed"));
    }

    P11_debug_msg("load_module: fun_list->C_Initialize");
    rv = fun_list->C_Initialize(NULL);
    if (rv != CKR_OK) {
      P11_debug_msg("load_module: fun_list->C_Initialize failed");
      enif_release_resource(p11_module_rt);
      return P11_error(env, "C_Initialize", rv);
    }

    /* Store the module and function list in resource */
    p11_module_rt->p11_module = pkcs11_lib;
    p11_module_rt->fun_list = fun_list;
    ERL_NIF_TERM p11_module_term = enif_make_resource(env, p11_module_rt);

    P11_debug_msg("load_module: return");
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), p11_module_term);
}

/* Implementation of list_slots/2: List the slots of a token with C_GetSlotList. */
static ERL_NIF_TERM list_slots(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

    CK_RV rv;
    CK_BBOOL token_present;
    p11_module_t* p11_module;
    CK_ULONG slot_count;
    CK_SLOT_ID_PTR slot_ids;
    CK_SLOT_INFO slot_info;
    ERL_NIF_TERM res = enif_make_list(env, 0);

    REQUIRE_ARGS(env, argc, 2);

    if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
      return enif_make_badarg(env);
    }
    BOOL_ARG(env, argv[1], token_present);

    /* This actually only counts the slots */
    P11_call(rv, p11_module, C_GetSlotList, CK_FALSE, NULL_PTR, &slot_count);
    if (rv != CKR_OK) {
      return P11_error(env, "C_GetSlotList", rv);
    }

    slot_ids = (CK_SLOT_ID_PTR) malloc(slot_count * sizeof(CK_SLOT_ID));

    P11_call(rv, p11_module, C_GetSlotList, token_present, slot_ids, &slot_count);
    if (rv != CKR_OK) {
      free(slot_ids);
      return P11_error(env, "C_GetSlotList", rv);
    }

    for (CK_ULONG i = 0; i < slot_count; i++) {
      ERL_NIF_TERM t;

      P11_call(rv, p11_module, C_GetSlotInfo, slot_ids[i], &slot_info);
      if (rv != CKR_OK) {
        free(slot_ids);
        return P11_error(env, "C_GetSlotInfo", rv);
      }

      t = enif_make_tuple6(env,
        enif_make_ulong(env, slot_ids[i]),
        to_elixir_string(env, slot_info.slotDescription),
        to_elixir_string(env, slot_info.manufacturerID),
        wrap_version(env, slot_info.hardwareVersion),
        wrap_version(env, slot_info.firmwareVersion),
        enif_make_ulong(env, slot_info.flags));
      res = enif_make_list_cell(env, t, res);
    }

    free(slot_ids);
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), res);
}

/* Implementation of token_info/2: Get the token info of a slot with C_GetTokenInfo. */
static ERL_NIF_TERM token_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv;
  CK_ULONG slot_id;
  CK_TOKEN_INFO token_info;
  p11_module_t* p11_module;
  ERL_NIF_TERM map = enif_make_new_map(env);

  REQUIRE_ARGS(env, argc, 2);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  ULONG_ARG(env, argv[1], slot_id);

  P11_call(rv, p11_module, C_GetTokenInfo, slot_id, &token_info);
  if (rv != CKR_OK) {
    return P11_error(env, "C_GetTokenInfo", rv);
  }

  enif_make_map_put(env, map, 
    enif_make_atom(env, "label"), 
    to_elixir_string(env, token_info.label), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "manufacturer_id"), 
    to_elixir_string(env, token_info.manufacturerID), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "model"), 
    to_elixir_string(env, token_info.model), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "serial_number"), 
    to_elixir_string(env, token_info.serialNumber), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "flags"), 
    enif_make_ulong(env, token_info.flags), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "max_session_count"), 
    enif_make_ulong(env, token_info.ulMaxSessionCount), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "session_count"), 
    enif_make_ulong(env, token_info.ulSessionCount), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "max_rw_session_count"), 
    enif_make_ulong(env, token_info.ulMaxRwSessionCount), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "rw_session_count"), 
    enif_make_ulong(env, token_info.ulRwSessionCount), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "max_pin_len"), 
    enif_make_ulong(env, token_info.ulMaxPinLen), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "min_pin_len"), 
    enif_make_ulong(env, token_info.ulMinPinLen), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "total_public_memory"), 
    enif_make_ulong(env, token_info.ulTotalPublicMemory), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "free_public_memory"), 
    enif_make_ulong(env, token_info.ulFreePublicMemory), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "total_private_memory"), 
    enif_make_ulong(env, token_info.ulTotalPrivateMemory), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "free_private_memory"), 
    enif_make_ulong(env, token_info.ulFreePrivateMemory), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "hardware_version"), 
    wrap_version(env, token_info.hardwareVersion), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "firmware_version"), 
    wrap_version(env, token_info.firmwareVersion), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "utc_time"), 
    to_elixir_string(env, token_info.utcTime), &map);

  return enif_make_tuple2(env, enif_make_atom(env, "ok"), map);
}

static ERL_NIF_TERM open_session(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv;
  CK_ULONG slot_id;
  CK_FLAGS flags;
  p11_module_t* p11_module;
  p11_session_t* p11_session;

  REQUIRE_ARGS(env, argc, 3);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  ULONG_ARG(env, argv[1], slot_id);
  ULONG_ARG(env, argv[2], flags);

  p11_session = (p11_session_t*) enif_alloc_resource(p11_session_resource_type, sizeof(p11_session_t));

  P11_call(rv, p11_module, C_OpenSession, slot_id, CKF_SERIAL_SESSION | flags, NULL_PTR, NULL_PTR, &p11_session->session_handle);
  if (rv != CKR_OK) {
    enif_release_resource(p11_session);
    return P11_error(env, "C_OpenSession", rv);
  }

  return enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_resource(env, p11_session));
}

static ERL_NIF_TERM close_session(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv;
  p11_session_t* p11_session;
  p11_module_t* p11_module;

  REQUIRE_ARGS(env, argc, 2);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_resource(env, argv[1], p11_session_resource_type, (void**)&p11_session)) {
    return enif_make_badarg(env);
  }

  P11_call(rv, p11_module, C_CloseSession, p11_session->session_handle);
  if (rv != CKR_OK) {
    return P11_error(env, "C_CloseSession", rv);
  }

  enif_release_resource(p11_session);
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM session_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv;
  p11_session_t* p11_session;
  p11_module_t* p11_module;
  CK_SESSION_INFO session_info;
  ERL_NIF_TERM result;

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_resource(env, argv[1], p11_session_resource_type, (void**)&p11_session)) {
    return enif_make_badarg(env);
  }

  P11_call(rv, p11_module, C_GetSessionInfo, p11_session->session_handle, &session_info);
  if (rv != CKR_OK) {
    return P11_error(env, "C_GetSessionInfo", rv);
  }

  result = enif_make_new_map(env);
  enif_make_map_put(env, result, 
    enif_make_atom(env, "slot_id"),
    enif_make_ulong(env, session_info.slotID), &result);
  enif_make_map_put(env, result, 
    enif_make_atom(env, "state"),
    enif_make_ulong(env, session_info.state), &result);
  enif_make_map_put(env, result, 
    enif_make_atom(env, "flags"),
    enif_make_ulong(env, session_info.flags), &result);
  enif_make_map_put(env, result, 
    enif_make_atom(env, "device_error"),
    enif_make_ulong(env, session_info.ulDeviceError), &result);

  return enif_make_tuple2(env, enif_make_atom(env, "ok"), result);
}

static ERL_NIF_TERM session_login(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv;
  p11_session_t* p11_session;
  p11_module_t* p11_module;
  CK_USER_TYPE user_type;
  char pin[256];

  REQUIRE_ARGS(env, argc, 4);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_resource(env, argv[1], p11_session_resource_type, (void**)&p11_session)) {
    return enif_make_badarg(env);
  }

  ULONG_ARG(env, argv[2], user_type);

  if (!enif_get_string(env, argv[3], (char *) &pin, sizeof(pin), ERL_NIF_UTF8)) {
    return enif_make_badarg(env);
  }

  P11_call(rv, p11_module, C_Login, p11_session->session_handle, 
                                    user_type, 
                                    (CK_UTF8CHAR_PTR)pin, 
                                    strlen(pin));
  if (rv != CKR_OK) {
    return P11_error(env, "C_Login", rv);
  } 

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM session_logout(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv;
  p11_session_t* p11_session;
  p11_module_t* p11_module;

  REQUIRE_ARGS(env, argc, 2);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  } 

  if (!enif_get_resource(env, argv[1], p11_session_resource_type, (void**)&p11_session)) {
    return enif_make_badarg(env);
  }

  P11_call(rv, p11_module, C_Logout, p11_session->session_handle);
  if (rv != CKR_OK) {
    return P11_error(env, "C_Logout", rv);
  }

  return enif_make_atom(env, "ok");
}

/* NIF module callbacks */
static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
    const char* mod_name = "P11exLib";
    int flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;

    P11_debug_msg("NIF load: enter");

    p11_module_resource_type = 
        enif_open_resource_type(env, NULL, mod_name, resource_cleanup, flags, NULL);
    
    if (p11_module_resource_type == NULL) {
        return -1;
    }

    // Add initialization for session resource type
    p11_session_resource_type = 
        enif_open_resource_type(env, NULL, mod_name, resource_cleanup, flags, NULL);
    
    if (p11_session_resource_type == NULL) {
        return -1;
    }

    P11_debug_msg("NIF load: success");
    return 0;
}

static void unload(ErlNifEnv* caller_env, void* priv_data) {

  P11_debug_msg("unload: (not doing anything)");
}

ERL_NIF_INIT(Elixir.P11ex.Lib, nif_funcs, load, NULL, NULL, unload)

/* helper functions */

static ERL_NIF_TERM to_elixir_string(ErlNifEnv *env, CK_UTF8CHAR_PTR utf8_array) {
    ERL_NIF_TERM ex_binary;
    size_t utf8_length = sizeof(utf8_array);
    unsigned char *bin_data = enif_make_new_binary(env, utf8_length, &ex_binary);
    memcpy(bin_data, utf8_array, utf8_length);
    return ex_binary;
}

/* Return an Erlang atom for a CK_RV error code. */
static ERL_NIF_TERM
ckr_to_atom(ErlNifEnv* env, CK_RV rv) {
    switch(rv) {
        case CKR_OK:                             return enif_make_atom(env, "ckr_ok");
        case CKR_CANCEL:                         return enif_make_atom(env, "ckr_cancel");
        case CKR_HOST_MEMORY:                    return enif_make_atom(env, "ckr_host_memory");
        case CKR_SLOT_ID_INVALID:                return enif_make_atom(env, "ckr_slot_id_invalid");
        case CKR_GENERAL_ERROR:                  return enif_make_atom(env, "ckr_general_error");
        case CKR_FUNCTION_FAILED:                return enif_make_atom(env, "ckr_function_failed");
        case CKR_ARGUMENTS_BAD:                  return enif_make_atom(env, "ckr_arguments_bad");
        case CKR_NO_EVENT:                       return enif_make_atom(env, "ckr_no_event");
        case CKR_NEED_TO_CREATE_THREADS:         return enif_make_atom(env, "ckr_need_to_create_threads");
        case CKR_CANT_LOCK:                      return enif_make_atom(env, "ckr_cant_lock");
        case CKR_ATTRIBUTE_READ_ONLY:            return enif_make_atom(env, "ckr_attribute_read_only");
        case CKR_ATTRIBUTE_SENSITIVE:            return enif_make_atom(env, "ckr_attribute_sensitive");
        case CKR_ATTRIBUTE_TYPE_INVALID:         return enif_make_atom(env, "ckr_attribute_type_invalid");
        case CKR_ATTRIBUTE_VALUE_INVALID:        return enif_make_atom(env, "ckr_attribute_value_invalid");
        case CKR_ACTION_PROHIBITED:              return enif_make_atom(env, "ckr_action_prohibited");
        case CKR_DATA_INVALID:                   return enif_make_atom(env, "ckr_data_invalid");
        case CKR_DATA_LEN_RANGE:                 return enif_make_atom(env, "ckr_data_len_range");
        case CKR_DEVICE_ERROR:                   return enif_make_atom(env, "ckr_device_error");
        case CKR_DEVICE_MEMORY:                  return enif_make_atom(env, "ckr_device_memory");
        case CKR_DEVICE_REMOVED:                 return enif_make_atom(env, "ckr_device_removed");
        case CKR_ENCRYPTED_DATA_INVALID:         return enif_make_atom(env, "ckr_encrypted_data_invalid");
        case CKR_ENCRYPTED_DATA_LEN_RANGE:       return enif_make_atom(env, "ckr_encrypted_data_len_range");
        case CKR_AEAD_DECRYPT_FAILED:            return enif_make_atom(env, "ckr_aead_decrypt_failed");
        case CKR_FUNCTION_CANCELED:              return enif_make_atom(env, "ckr_function_canceled");
        case CKR_FUNCTION_NOT_PARALLEL:          return enif_make_atom(env, "ckr_function_not_parallel");
        case CKR_FUNCTION_NOT_SUPPORTED:         return enif_make_atom(env, "ckr_function_not_supported");
        case CKR_KEY_HANDLE_INVALID:             return enif_make_atom(env, "ckr_key_handle_invalid");
        case CKR_KEY_SIZE_RANGE:                 return enif_make_atom(env, "ckr_key_size_range");
        case CKR_KEY_TYPE_INCONSISTENT:          return enif_make_atom(env, "ckr_key_type_inconsistent");
        case CKR_KEY_NOT_NEEDED:                 return enif_make_atom(env, "ckr_key_not_needed");
        case CKR_KEY_CHANGED:                    return enif_make_atom(env, "ckr_key_changed");
        case CKR_KEY_NEEDED:                     return enif_make_atom(env, "ckr_key_needed");
        case CKR_KEY_INDIGESTIBLE:               return enif_make_atom(env, "ckr_key_indigestible");
        case CKR_KEY_FUNCTION_NOT_PERMITTED:     return enif_make_atom(env, "ckr_key_function_not_permitted");
        case CKR_KEY_NOT_WRAPPABLE:              return enif_make_atom(env, "ckr_key_not_wrappable");
        case CKR_KEY_UNEXTRACTABLE:              return enif_make_atom(env, "ckr_key_unextractable");
        case CKR_MECHANISM_INVALID:              return enif_make_atom(env, "ckr_mechanism_invalid");
        case CKR_MECHANISM_PARAM_INVALID:        return enif_make_atom(env, "ckr_mechanism_param_invalid");
        case CKR_OBJECT_HANDLE_INVALID:          return enif_make_atom(env, "ckr_object_handle_invalid");
        case CKR_OPERATION_ACTIVE:               return enif_make_atom(env, "ckr_operation_active");
        case CKR_OPERATION_NOT_INITIALIZED:      return enif_make_atom(env, "ckr_operation_not_initialized");
        case CKR_PIN_INCORRECT:                  return enif_make_atom(env, "ckr_pin_incorrect");
        case CKR_PIN_INVALID:                    return enif_make_atom(env, "ckr_pin_invalid");
        case CKR_PIN_LEN_RANGE:                  return enif_make_atom(env, "ckr_pin_len_range");
        case CKR_PIN_EXPIRED:                    return enif_make_atom(env, "ckr_pin_expired");
        case CKR_PIN_LOCKED:                     return enif_make_atom(env, "ckr_pin_locked");
        case CKR_SESSION_CLOSED:                 return enif_make_atom(env, "ckr_session_closed");
        case CKR_SESSION_COUNT:                  return enif_make_atom(env, "ckr_session_count");
        case CKR_SESSION_HANDLE_INVALID:         return enif_make_atom(env, "ckr_session_handle_invalid");
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return enif_make_atom(env, "ckr_session_parallel_not_supported");
        case CKR_SESSION_READ_ONLY:              return enif_make_atom(env, "ckr_session_read_only");
        case CKR_SESSION_EXISTS:                 return enif_make_atom(env, "ckr_session_exists");
        case CKR_SESSION_READ_ONLY_EXISTS:       return enif_make_atom(env, "ckr_session_read_only_exists");
        case CKR_SESSION_READ_WRITE_SO_EXISTS:   return enif_make_atom(env, "ckr_session_read_write_so_exists");
        case CKR_SIGNATURE_INVALID:              return enif_make_atom(env, "ckr_signature_invalid");
        case CKR_SIGNATURE_LEN_RANGE:            return enif_make_atom(env, "ckr_signature_len_range");
        case CKR_TEMPLATE_INCOMPLETE:            return enif_make_atom(env, "ckr_template_incomplete");
        case CKR_TEMPLATE_INCONSISTENT:          return enif_make_atom(env, "ckr_template_inconsistent");
        case CKR_TOKEN_NOT_PRESENT:              return enif_make_atom(env, "ckr_token_not_present");
        case CKR_TOKEN_NOT_RECOGNIZED:           return enif_make_atom(env, "ckr_token_not_recognized");
        case CKR_TOKEN_WRITE_PROTECTED:          return enif_make_atom(env, "ckr_token_write_protected");
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID:  return enif_make_atom(env, "ckr_unwrapping_key_handle_invalid");
        case CKR_UNWRAPPING_KEY_SIZE_RANGE:      return enif_make_atom(env, "ckr_unwrapping_key_size_range");
        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return enif_make_atom(env, "ckr_unwrapping_key_type_inconsistent");
        case CKR_USER_ALREADY_LOGGED_IN:         return enif_make_atom(env, "ckr_user_already_logged_in");
        case CKR_USER_NOT_LOGGED_IN:             return enif_make_atom(env, "ckr_user_not_logged_in");
        case CKR_USER_PIN_NOT_INITIALIZED:       return enif_make_atom(env, "ckr_user_pin_not_initialized");
        case CKR_USER_TYPE_INVALID:              return enif_make_atom(env, "ckr_user_type_invalid");
        case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return enif_make_atom(env, "ckr_user_another_already_logged_in");
        case CKR_USER_TOO_MANY_TYPES:            return enif_make_atom(env, "ckr_user_too_many_types");
        case CKR_WRAPPED_KEY_INVALID:            return enif_make_atom(env, "ckr_wrapped_key_invalid");
        case CKR_WRAPPED_KEY_LEN_RANGE:          return enif_make_atom(env, "ckr_wrapped_key_len_range");
        case CKR_WRAPPING_KEY_HANDLE_INVALID:    return enif_make_atom(env, "ckr_wrapping_key_handle_invalid");
        case CKR_WRAPPING_KEY_SIZE_RANGE:        return enif_make_atom(env, "ckr_wrapping_key_size_range");
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return enif_make_atom(env, "ckr_wrapping_key_type_inconsistent");
        case CKR_RANDOM_SEED_NOT_SUPPORTED:      return enif_make_atom(env, "ckr_random_seed_not_supported");
        case CKR_RANDOM_NO_RNG:                  return enif_make_atom(env, "ckr_random_no_rng");
        case CKR_DOMAIN_PARAMS_INVALID:          return enif_make_atom(env, "ckr_domain_params_invalid");
        case CKR_CURVE_NOT_SUPPORTED:            return enif_make_atom(env, "ckr_curve_not_supported");
        case CKR_BUFFER_TOO_SMALL:               return enif_make_atom(env, "ckr_buffer_too_small");
        case CKR_SAVED_STATE_INVALID:            return enif_make_atom(env, "ckr_saved_state_invalid");
        case CKR_INFORMATION_SENSITIVE:          return enif_make_atom(env, "ckr_information_sensitive");
        case CKR_STATE_UNSAVEABLE:               return enif_make_atom(env, "ckr_state_unsaveable");
        case CKR_CRYPTOKI_NOT_INITIALIZED:       return enif_make_atom(env, "ckr_cryptoki_not_initialized");
        case CKR_CRYPTOKI_ALREADY_INITIALIZED:   return enif_make_atom(env, "ckr_cryptoki_already_initialized");
        case CKR_MUTEX_BAD:                      return enif_make_atom(env, "ckr_mutex_bad");
        case CKR_MUTEX_NOT_LOCKED:               return enif_make_atom(env, "ckr_mutex_not_locked");
        case CKR_NEW_PIN_MODE:                   return enif_make_atom(env, "ckr_new_pin_mode");
        case CKR_NEXT_OTP:                       return enif_make_atom(env, "ckr_next_otp");
        case CKR_EXCEEDED_MAX_ITERATIONS:        return enif_make_atom(env, "ckr_exceeded_max_iterations");
        case CKR_FIPS_SELF_TEST_FAILED:          return enif_make_atom(env, "ckr_fips_self_test_failed");
        case CKR_LIBRARY_LOAD_FAILED:            return enif_make_atom(env, "ckr_library_load_failed");
        case CKR_PIN_TOO_WEAK:                   return enif_make_atom(env, "ckr_pin_too_weak");
        case CKR_PUBLIC_KEY_INVALID:             return enif_make_atom(env, "ckr_public_key_invalid");
        case CKR_FUNCTION_REJECTED:              return enif_make_atom(env, "ckr_function_rejected");
        case CKR_TOKEN_RESOURCE_EXCEEDED:        return enif_make_atom(env, "ckr_token_resource_exceeded");
        case CKR_OPERATION_CANCEL_FAILED:        return enif_make_atom(env, "ckr_operation_cancel_failed");
        case CKR_KEY_EXHAUSTED:                  return enif_make_atom(env, "ckr_key_exhausted");
        default:                                 return enif_make_tuple2(env, 
                                                    enif_make_atom(env, "ckr_vendor_defined"),
                                                    enif_make_uint(env, rv));
    }
} 

