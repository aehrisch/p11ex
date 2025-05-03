#include <erl_nif.h>
#include <string.h>
#include <stdio.h>

#include <dlfcn.h>

#include "p11.h"

#define MAX_ATTRIBUTE_NAME_LENGTH 64
#define MAX_OBJECT_CLASS_NAME_LENGTH 64
#define MAX_KEY_TYPE_NAME_LENGTH 64
#define MAX_MECHANISM_NAME_LENGTH 128
#define MAX_PIN_LENGTH 256
#define FIND_OBJ_MAX_HITS 8192
#define ATTRIBUTE_BUFFER_SIZE 4096

/* debugging macros */

# define P11_DEBUG 1

#define P11_debug(format, ...) \
  if (P11_DEBUG) { \
    enif_fprintf(stderr, "P11_debug: " format "\n", ##__VA_ARGS__); \
    fflush(stderr); \
  }

void print_mechanism(CK_MECHANISM_PTR mechanism) {
  fprintf(stderr, "%%Mechanism{\n");
  fprintf(stderr, "  mechanism: 0x%lx\n", mechanism->mechanism); 
  fprintf(stderr, "  pParameter: %p\n", mechanism->pParameter);
  fprintf(stderr, "  ulParameterLen: %lu\n", mechanism->ulParameterLen);
  fprintf(stderr, "}\n");
}

void print_attribute(CK_ATTRIBUTE* attribute) {
  fprintf(stderr, "%%Attribute{\n");
  fprintf(stderr, "  type: 0x%lx\n", attribute->type);
  fprintf(stderr, "  pValue: %p\n", attribute->pValue);
  fprintf(stderr, "  ulValueLen: %lu\n", attribute->ulValueLen);
  fprintf(stderr, "}\n");
}

void print_buffer(const void* buffer, size_t length) {
  const unsigned char* data = (const unsigned char*)buffer;
  fprintf(stderr, "Buffer at %p, length %zu bytes:\n", buffer, length);
  
  for (size_t offset = 0; offset < length; offset += 16) {
    /* Print offset */
    fprintf(stderr, "%08zx  ", offset);
    
    /* Print hex values */
    for (size_t i = 0; i < 16; i++) {
      if (offset + i < length) {
        fprintf(stderr, "%02x ", data[offset + i]);
      } else {
        fprintf(stderr, "   "); /* Padding for incomplete line */
      }
      if (i == 7) fprintf(stderr, " "); /* Extra space between 8-byte groups */
    }
    
    /* Print ASCII representation */
    fprintf(stderr, " |");
    for (size_t i = 0; i < 16; i++) {
      if (offset + i < length) {
        unsigned char c = data[offset + i];
        /* Print only printable ASCII characters, replace others with dots */
        fprintf(stderr, "%c", (c >= 32 && c <= 126) ? c : '.');
      } else {
        fprintf(stderr, " "); /* Padding for incomplete line */
      }
    }
    fprintf(stderr, "|\n");
  }
  fflush(stderr);
}

#define P11_debug_mechanism(mechanism) \
  if (P11_DEBUG) { \
    print_mechanism(mechanism); \
  }

#define P11_debug_attribute(attribute) \
  if (P11_DEBUG) { \
    print_attribute(attribute); \
  }

#define P11_debug_buffer(buffer, length) \
  if (P11_DEBUG) { \
    print_buffer(buffer, length); \
  }

/* macro that creates an error tuple with the function name and the error code */
#define P11_error(env, fname, rv) \
    (enif_make_tuple2(env, \
      enif_make_atom(env, "error"), \
      enif_make_tuple2(env, enif_make_atom(env, fname), ckr_to_atom(env, rv))))

#define P11_call(rv, p11_module, func, args...) \
    if (P11_DEBUG) { \
      fprintf(stderr, "P11_call: module=%p, func=%s\n", p11_module, #func); \
      fflush(stderr); \
    } \
    rv = p11_module->fun_list->func(args); \
    if (P11_DEBUG) { \
      fprintf(stderr, "P11_call: %s returned 0x%lu (%s)\n", #func, rv, ckr_to_string(rv)); \
      fflush(stderr); \
    }

/* general purpose macros */

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
    bool_var = (enif_compare(term, enif_make_atom(env, "true")) == 0) ? CK_TRUE : CK_FALSE;

/* macro that checks if the argument is an Erlang number, and if so, converts it to CK_ULONG. */
#define ULONG_ARG(env, term, ulong_var) \
    if (!enif_is_number(env, term)) { \
      return enif_make_badarg(env); \
    } \
    enif_get_ulong(env, term, &ulong_var);

/* macro that wraps a CK_VERSION into a tuple */
#define wrap_version(env, v) \
    (enif_make_tuple2(env, enif_make_int(env, v.major), enif_make_int(env, v.minor)))

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* struct that holds the PKCS#11 module and the function list */
typedef struct {
   void *p11_module;
   CK_FUNCTION_LIST_PTR fun_list;
} p11_module_t;

#define P11_ATTR_TYPE_STRING 1
#define P11_ATTR_TYPE_ULONG  2
#define P11_ATTR_TYPE_LONG   3
#define P11_ATTR_TYPE_BIGINT 4
#define P11_ATTR_TYPE_BOOL   5
#define P11_ATTR_TYPE_BYTES  6
#define P11_ATTR_TYPE_DATE   7
#define P11_ATTR_TYPE_CLASS  8
#define P11_ATTR_TYPE_KEY    9
#define P11_ATTR_TYPE_MECHANISM 10

/* internal representation of a CK_ATTRIBUTE, not exported to Erlang */
typedef struct {
  CK_ATTRIBUTE_TYPE id;
  const char *name;
  CK_ULONG value_type;
} attribute_info_t;

/* internal representation of a CK_OBJECT_CLASS, not exported to Erlang */
typedef struct {
    const char *name;
    CK_OBJECT_CLASS value;
} object_class_map_t;

/* internal representation of a CK_MECHANISM, not exported to Erlang */
typedef struct {
    const char *name;
    CK_MECHANISM_TYPE value;
} mechanism_map_t;

/* internal representation of a CK_KEY_TYPE, not exported to Erlang */
typedef struct {
    const char *name;
    CK_KEY_TYPE value;
} key_type_map_t;

/* Representation of a PKCS#11 module. This one is exported to Erlang. */
static ErlNifResourceType *p11_module_resource_type = NULL;

/* Forward declarations for functions that accessible from Erlang */
static ERL_NIF_TERM load_module(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM list_slots(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM token_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM finalize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM open_session(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM close_session(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM close_all_sessions(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM session_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM session_login(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM session_logout(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM find_objects(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM generate_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM encrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM encrypt_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM encrypt_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM encrypt_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM decrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM decrypt_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM decrypt_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM decrypt_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM generate_random(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM sign_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sign_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sign_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM verify_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM digest_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM digest_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM digest_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM digest(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM generate_key_pair(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM destroy_object(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM list_mechanisms(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM mechanism_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

/* Forward declarations for functions that are internal to this module */
void resource_cleanup(ErlNifEnv* env, void* obj);
static ERL_NIF_TERM p11str_to_term(ErlNifEnv* env, CK_UTF8CHAR_PTR utf8_array, size_t max_length);
static ERL_NIF_TERM ckr_to_atom(ErlNifEnv* env, CK_RV rv);
static const char* ckr_to_string(CK_RV rv);

static ERL_NIF_TERM ckm_to_atom(ErlNifEnv* env, CK_MECHANISM_TYPE ckm);
static int mechanism_type_from_term(ErlNifEnv* env, ERL_NIF_TERM term, 
  CK_MECHANISM_TYPE_PTR mechanism_type);
static ERL_NIF_TERM set_mechanism_parameters_from_term(ErlNifEnv* env, 
  ERL_NIF_TERM mech_name_term, ERL_NIF_TERM map, 
  CK_MECHANISM_TYPE mech_type, CK_MECHANISM_PTR mechanism);

static ERL_NIF_TERM term_to_attributes(
  ErlNifEnv* env, ERL_NIF_TERM term_list,
  CK_ATTRIBUTE** out_attribute_list,
  CK_ULONG_PTR out_attribute_count);
static ERL_NIF_TERM term_to_mechanism(ErlNifEnv* env, ERL_NIF_TERM term, CK_MECHANISM_PTR mechanism);
static int is_boolean(ErlNifEnv* env, ERL_NIF_TERM term);
static unsigned copy_attribute_value(ErlNifEnv* env, ERL_NIF_TERM term, attribute_info_t* attribute_info, CK_VOID_PTR value, unsigned remaining_size);
static attribute_info_t *find_attribute_info_by_id(CK_ULONG attribute_id);
static attribute_info_t *find_attribute_info_by_name(const char *name);

static ERL_NIF_TERM attribute_to_term(ErlNifEnv* env, CK_ATTRIBUTE* attribute);
static ERL_NIF_TERM get_object_attributes(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM term_to_attrib_template(
  ErlNifEnv* env, ERL_NIF_TERM term_list,
  CK_ATTRIBUTE_PTR* out_attribute_list,
  CK_ULONG_PTR out_attribute_count);

static void secure_zero(void* ptr, size_t len);

static int object_class_from_term(ErlNifEnv* env, ERL_NIF_TERM term, CK_OBJECT_CLASS* out_object_class);
static ERL_NIF_TERM object_class_to_term(ErlNifEnv* env, CK_OBJECT_CLASS object_class);

static int key_type_from_term(ErlNifEnv* env, ERL_NIF_TERM term, CK_KEY_TYPE* out_key_type);
static ERL_NIF_TERM key_type_to_term(ErlNifEnv* env, CK_KEY_TYPE key_type);

static const attribute_info_t attribute_info[] = {
  {CKA_AC_ISSUER,   "cka_ac_issuer",   P11_ATTR_TYPE_BYTES},
  {CKA_ALWAYS_AUTHENTICATE, "cka_always_authenticate", P11_ATTR_TYPE_BOOL},
  {CKA_ALWAYS_SENSITIVE, "cka_always_sensitive", P11_ATTR_TYPE_BOOL},
  {CKA_APPLICATION, "cka_application", P11_ATTR_TYPE_STRING},
  {CKA_ATTR_TYPES,  "cka_attr_types",  P11_ATTR_TYPE_BYTES},
  {CKA_BASE,        "cka_base",        P11_ATTR_TYPE_BIGINT},
  {CKA_CERTIFICATE_CATEGORY, "cka_certificate_category", P11_ATTR_TYPE_ULONG},
  {CKA_CERTIFICATE_TYPE, "cka_certificate_type", P11_ATTR_TYPE_ULONG},
  {CKA_CHECK_VALUE, "cka_check_value", P11_ATTR_TYPE_BYTES},
  {CKA_CLASS,       "cka_class",       P11_ATTR_TYPE_CLASS},
  {CKA_COEFFICIENT, "cka_coefficient", P11_ATTR_TYPE_BIGINT},
  {CKA_COPYABLE,    "cka_copyable", P11_ATTR_TYPE_BOOL},
  {CKA_DECRYPT,     "cka_decrypt",     P11_ATTR_TYPE_BOOL},
  {CKA_DERIVE,      "cka_derive",      P11_ATTR_TYPE_BOOL},
  {CKA_DESTROYABLE, "cka_destroyable", P11_ATTR_TYPE_BOOL},
  {CKA_EC_PARAMS,    "cka_ec_params",    P11_ATTR_TYPE_BYTES},
  {CKA_EC_POINT,     "cka_ec_point",     P11_ATTR_TYPE_BYTES},  
  {CKA_ECDSA_PARAMS, "cka_ecdsa_params", P11_ATTR_TYPE_BYTES},
  {CKA_ENCRYPT,     "cka_encrypt",     P11_ATTR_TYPE_BOOL},
  {CKA_END_DATE,    "cka_end_date",    P11_ATTR_TYPE_DATE},
  {CKA_EXPONENT_1,  "cka_exponent_1",  P11_ATTR_TYPE_BIGINT},
  {CKA_EXPONENT_2,  "cka_exponent_2",  P11_ATTR_TYPE_BIGINT},
  {CKA_EXTRACTABLE, "cka_extractable", P11_ATTR_TYPE_BOOL},
  {CKA_HASH_OF_ISSUER_PUBLIC_KEY, "cka_hash_of_issuer_public_key", P11_ATTR_TYPE_BYTES},
  {CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "cka_hash_of_subject_public_key", P11_ATTR_TYPE_BYTES},
  {CKA_ID,          "cka_id",          P11_ATTR_TYPE_BYTES},
  {CKA_ISSUER,      "cka_issuer",      P11_ATTR_TYPE_BYTES},
  {CKA_JAVA_MIDP_SECURITY_DOMAIN, "cka_java_midp_security_domain", P11_ATTR_TYPE_ULONG},
  {CKA_KEY_GEN_MECHANISM, "cka_key_gen_mechanism", P11_ATTR_TYPE_MECHANISM},
  {CKA_KEY_TYPE,    "cka_key_type",    P11_ATTR_TYPE_KEY},
  {CKA_LABEL,       "cka_label",       P11_ATTR_TYPE_STRING},
  {CKA_LOCAL,       "cka_local",       P11_ATTR_TYPE_BOOL},
  {CKA_MODIFIABLE,  "cka_modifiable", P11_ATTR_TYPE_BOOL},
  {CKA_MODULUS_BITS, "cka_modulus_bits", P11_ATTR_TYPE_ULONG},
  {CKA_MODULUS,     "cka_modulus",     P11_ATTR_TYPE_BIGINT},
  {CKA_NAME_HASH_ALGORITHM, "cka_name_hash_algorithm", P11_ATTR_TYPE_ULONG},
  {CKA_NEVER_EXTRACTABLE, "cka_never_extractable", P11_ATTR_TYPE_BOOL},
  {CKA_OBJECT_ID,   "cka_object_id",   P11_ATTR_TYPE_BYTES},
  {CKA_OWNER,       "cka_owner",       P11_ATTR_TYPE_BYTES},
  {CKA_PRIME_1,     "cka_prime_1",     P11_ATTR_TYPE_BIGINT},
  {CKA_PRIME_2,     "cka_prime_2",     P11_ATTR_TYPE_BIGINT},
  {CKA_PRIME_BITS,  "cka_prime_bits", P11_ATTR_TYPE_ULONG},
  {CKA_PRIME,       "cka_prime",       P11_ATTR_TYPE_BIGINT},
  {CKA_PRIVATE_EXPONENT, "cka_private_exponent", P11_ATTR_TYPE_BIGINT},
  {CKA_PRIVATE,     "cka_private",     P11_ATTR_TYPE_BOOL},
  {CKA_PUBLIC_EXPONENT, "cka_public_exponent", P11_ATTR_TYPE_BYTES},
  {CKA_PUBLIC_KEY_INFO, "cka_public_key_info", P11_ATTR_TYPE_BYTES},
  {CKA_SENSITIVE,   "cka_sensitive",   P11_ATTR_TYPE_BOOL},
  {CKA_SERIAL_NUMBER, "cka_serial_number", P11_ATTR_TYPE_BYTES},
  {CKA_SIGN_RECOVER, "cka_sign_recover", P11_ATTR_TYPE_BOOL},
  {CKA_SIGN,        "cka_sign",        P11_ATTR_TYPE_BOOL},
  {CKA_START_DATE,  "cka_start_date",  P11_ATTR_TYPE_DATE},
  {CKA_SUBJECT,     "cka_subject",     P11_ATTR_TYPE_BYTES},
  {CKA_SUBPRIME_BITS, "cka_subprime_bits", P11_ATTR_TYPE_ULONG},
  {CKA_SUBPRIME,    "cka_subprime",    P11_ATTR_TYPE_BIGINT},
  {CKA_TOKEN,       "cka_token",       P11_ATTR_TYPE_BOOL},
  {CKA_TRUSTED,     "cka_trusted",     P11_ATTR_TYPE_BOOL},
  {CKA_UNIQUE_ID,   "cka_unique_id",   P11_ATTR_TYPE_STRING},
  {CKA_UNWRAP,      "cka_unwrap",      P11_ATTR_TYPE_BOOL},
  {CKA_URL,         "cka_url",         P11_ATTR_TYPE_STRING},
  {CKA_VALUE_BITS,  "cka_value_bits", P11_ATTR_TYPE_ULONG},
  {CKA_VALUE_LEN,   "cka_value_len",   P11_ATTR_TYPE_ULONG},
  {CKA_VALUE,       "cka_value",       P11_ATTR_TYPE_BYTES},
  {CKA_VERIFY_RECOVER, "cka_verify_recover", P11_ATTR_TYPE_BOOL},
  {CKA_VERIFY,      "cka_verify",      P11_ATTR_TYPE_BOOL},
  {CKA_WRAP,        "cka_wrap",        P11_ATTR_TYPE_BOOL},
  {CKA_WRAP_WITH_TRUSTED, "cka_wrap_with_trusted", P11_ATTR_TYPE_BOOL}
};

#define ATTRIBUTE_INFO_COUNT (sizeof(attribute_info) / sizeof(attribute_info[0]))

static const object_class_map_t object_class_map[] = {
  {"cko_data", CKO_DATA},
  {"cko_certificate", CKO_CERTIFICATE},
  {"cko_public_key", CKO_PUBLIC_KEY},
  {"cko_private_key", CKO_PRIVATE_KEY},
  {"cko_secret_key", CKO_SECRET_KEY},
  {"cko_hw_feature", CKO_HW_FEATURE},
  {"cko_domain_parameters", CKO_DOMAIN_PARAMETERS},
  {"cko_mechanism", CKO_MECHANISM},
  {"cko_otp_key", CKO_OTP_KEY},
  {"cko_profile", CKO_PROFILE},
  {"cko_vendor_defined", CKO_VENDOR_DEFINED},
  {NULL, 0}
};

static const mechanism_map_t mechanism_map[] = {
    {"ckm_rsa_pkcs_key_pair_gen", CKM_RSA_PKCS_KEY_PAIR_GEN},
    {"ckm_rsa_pkcs", CKM_RSA_PKCS},
    {"ckm_rsa_9796", CKM_RSA_9796},
    {"ckm_rsa_x_509", CKM_RSA_X_509},
    {"ckm_md2_rsa_pkcs", CKM_MD2_RSA_PKCS},
    {"ckm_md5_rsa_pkcs", CKM_MD5_RSA_PKCS},
    {"ckm_sha1_rsa_pkcs", CKM_SHA1_RSA_PKCS},
    {"ckm_ripemd128_rsa_pkcs", CKM_RIPEMD128_RSA_PKCS},
    {"ckm_ripemd160_rsa_pkcs", CKM_RIPEMD160_RSA_PKCS},
    {"ckm_rsa_pkcs_oaep", CKM_RSA_PKCS_OAEP},
    {"ckm_rsa_x9_31_key_pair_gen", CKM_RSA_X9_31_KEY_PAIR_GEN},
    {"ckm_rsa_x9_31", CKM_RSA_X9_31},
    {"ckm_sha1_rsa_x9_31", CKM_SHA1_RSA_X9_31},
    {"ckm_rsa_pkcs_pss", CKM_RSA_PKCS_PSS},
    {"ckm_sha1_rsa_pkcs_pss", CKM_SHA1_RSA_PKCS_PSS},
    {"ckm_dsa_key_pair_gen", CKM_DSA_KEY_PAIR_GEN},
    {"ckm_dsa", CKM_DSA},
    {"ckm_dsa_sha1", CKM_DSA_SHA1},
    {"ckm_dsa_sha224", CKM_DSA_SHA224},
    {"ckm_dsa_sha256", CKM_DSA_SHA256},
    {"ckm_dsa_sha384", CKM_DSA_SHA384},
    {"ckm_dsa_sha512", CKM_DSA_SHA512},
    {"ckm_dsa_sha3_224", CKM_DSA_SHA3_224},
    {"ckm_dsa_sha3_256", CKM_DSA_SHA3_256},
    {"ckm_dsa_sha3_384", CKM_DSA_SHA3_384},
    {"ckm_dsa_sha3_512", CKM_DSA_SHA3_512},
    {"ckm_dh_pkcs_key_pair_gen", CKM_DH_PKCS_KEY_PAIR_GEN},
    {"ckm_dh_pkcs_derive", CKM_DH_PKCS_DERIVE},
    {"ckm_x9_42_dh_key_pair_gen", CKM_X9_42_DH_KEY_PAIR_GEN},
    {"ckm_x9_42_dh_derive", CKM_X9_42_DH_DERIVE},
    {"ckm_x9_42_dh_hybrid_derive", CKM_X9_42_DH_HYBRID_DERIVE},
    {"ckm_x9_42_mqv_derive", CKM_X9_42_MQV_DERIVE},
    {"ckm_sha256_rsa_pkcs", CKM_SHA256_RSA_PKCS},
    {"ckm_sha384_rsa_pkcs", CKM_SHA384_RSA_PKCS},
    {"ckm_sha512_rsa_pkcs", CKM_SHA512_RSA_PKCS},
    {"ckm_sha256_rsa_pkcs_pss", CKM_SHA256_RSA_PKCS_PSS},
    {"ckm_sha384_rsa_pkcs_pss", CKM_SHA384_RSA_PKCS_PSS},
    {"ckm_sha512_rsa_pkcs_pss", CKM_SHA512_RSA_PKCS_PSS},
    {"ckm_sha224_rsa_pkcs", CKM_SHA224_RSA_PKCS},
    {"ckm_sha224_rsa_pkcs_pss", CKM_SHA224_RSA_PKCS_PSS},
    {"ckm_sha512_224", CKM_SHA512_224},
    {"ckm_sha512_224_key_derivation", CKM_SHA512_224_KEY_DERIVATION},
    {"ckm_sha512_256", CKM_SHA512_256},
    {"ckm_sha512_256_key_derivation", CKM_SHA512_256_KEY_DERIVATION},
    {"ckm_sha512_t", CKM_SHA512_T},
    {"ckm_sha512_t_key_derivation", CKM_SHA512_T_KEY_DERIVATION},
    {"ckm_sha3_256_rsa_pkcs", CKM_SHA3_256_RSA_PKCS},
    {"ckm_sha3_384_rsa_pkcs", CKM_SHA3_384_RSA_PKCS},
    {"ckm_sha3_512_rsa_pkcs", CKM_SHA3_512_RSA_PKCS},
    {"ckm_sha3_256_rsa_pkcs_pss", CKM_SHA3_256_RSA_PKCS_PSS},
    {"ckm_sha3_384_rsa_pkcs_pss", CKM_SHA3_384_RSA_PKCS_PSS},
    {"ckm_sha3_512_rsa_pkcs_pss", CKM_SHA3_512_RSA_PKCS_PSS},
    {"ckm_sha3_224_rsa_pkcs", CKM_SHA3_224_RSA_PKCS},
    {"ckm_sha3_224_rsa_pkcs_pss", CKM_SHA3_224_RSA_PKCS_PSS},
    {"ckm_rc2_key_gen", CKM_RC2_KEY_GEN},
    {"ckm_rc2_ecb", CKM_RC2_ECB},
    {"ckm_rc2_cbc", CKM_RC2_CBC},
    {"ckm_rc2_mac", CKM_RC2_MAC},
    {"ckm_rc2_mac_general", CKM_RC2_MAC_GENERAL},
    {"ckm_rc2_cbc_pad", CKM_RC2_CBC_PAD},
    {"ckm_rc4_key_gen", CKM_RC4_KEY_GEN},
    {"ckm_rc4", CKM_RC4},
    {"ckm_des_key_gen", CKM_DES_KEY_GEN},
    {"ckm_des_ecb", CKM_DES_ECB},
    {"ckm_des_cbc", CKM_DES_CBC},
    {"ckm_des_mac", CKM_DES_MAC},
    {"ckm_des_mac_general", CKM_DES_MAC_GENERAL},
    {"ckm_des_cbc_pad", CKM_DES_CBC_PAD},

    {"ckm_aes_xts", CKM_AES_XTS},
    {"ckm_aes_xts_key_gen", CKM_AES_XTS_KEY_GEN},
    {"ckm_aes_key_gen", CKM_AES_KEY_GEN},
    {"ckm_aes_ecb", CKM_AES_ECB},
    {"ckm_aes_cbc", CKM_AES_CBC},
    {"ckm_aes_mac", CKM_AES_MAC},
    {"ckm_aes_mac_general", CKM_AES_MAC_GENERAL},
    {"ckm_aes_cbc_pad", CKM_AES_CBC_PAD},
    {"ckm_aes_ctr", CKM_AES_CTR},
    {"ckm_aes_gcm", CKM_AES_GCM},
    {"ckm_aes_ccm", CKM_AES_CCM},
    {"ckm_aes_cts", CKM_AES_CTS},
    {"ckm_aes_cmac", CKM_AES_CMAC},
    {"ckm_aes_cmac_general", CKM_AES_CMAC_GENERAL},
    {"ckm_aes_xcbc_mac", CKM_AES_XCBC_MAC},
    {"ckm_aes_xcbc_mac_96", CKM_AES_XCBC_MAC_96},
    {"ckm_aes_gmac", CKM_AES_GMAC},
    {"ckm_blowfish_key_gen", CKM_BLOWFISH_KEY_GEN},
    {"ckm_blowfish_cbc", CKM_BLOWFISH_CBC},
    {"ckm_twofish_key_gen", CKM_TWOFISH_KEY_GEN},
    {"ckm_twofish_cbc", CKM_TWOFISH_CBC},
    {"ckm_blowfish_cbc_pad", CKM_BLOWFISH_CBC_PAD},
    {"ckm_twofish_cbc_pad", CKM_TWOFISH_CBC_PAD},
    {"ckm_des_ecb_encrypt_data", CKM_DES_ECB_ENCRYPT_DATA},
    {"ckm_des_cbc_encrypt_data", CKM_DES_CBC_ENCRYPT_DATA},
    {"ckm_des3_ecb_encrypt_data", CKM_DES3_ECB_ENCRYPT_DATA},
    {"ckm_des3_cbc_encrypt_data", CKM_DES3_CBC_ENCRYPT_DATA},
    {"ckm_aes_ecb_encrypt_data", CKM_AES_ECB_ENCRYPT_DATA},
    {"ckm_aes_cbc_encrypt_data", CKM_AES_CBC_ENCRYPT_DATA},
    {"ckm_chacha20_key_gen", CKM_CHACHA20_KEY_GEN},
    {"ckm_chacha20", CKM_CHACHA20},
    {"ckm_poly1305_key_gen", CKM_POLY1305_KEY_GEN},
    {"ckm_poly1305", CKM_POLY1305},
    {"ckm_dsa_parameter_gen", CKM_DSA_PARAMETER_GEN},
    {"ckm_dh_pkcs_parameter_gen", CKM_DH_PKCS_PARAMETER_GEN},
    {"ckm_x9_42_dh_parameter_gen", CKM_X9_42_DH_PARAMETER_GEN},
    {"ckm_dsa_probabilistic_parameter_gen", CKM_DSA_PROBABILISTIC_PARAMETER_GEN},
    {"ckm_dsa_shawe_taylor_parameter_gen", CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN},
    {"ckm_dsa_fips_g_gen", CKM_DSA_FIPS_G_GEN},
    {"ckm_aes_ofb", CKM_AES_OFB},
    {"ckm_aes_cfb64", CKM_AES_CFB64},
    {"ckm_aes_cfb8", CKM_AES_CFB8},
    {"ckm_aes_cfb128", CKM_AES_CFB128},
    {"ckm_aes_cfb1", CKM_AES_CFB1},
    {"ckm_aes_key_wrap", CKM_AES_KEY_WRAP},
    {"ckm_aes_key_wrap_pad", CKM_AES_KEY_WRAP_PAD},
    {"ckm_aes_key_wrap_kwp", CKM_AES_KEY_WRAP_KWP},
    {"ckm_aes_key_wrap_pkcs7", CKM_AES_KEY_WRAP_PKCS7},

    /* SHA based HMAC algorithms */
    {"ckm_sha1_hmac", CKM_SHA_1_HMAC},
    {"ckm_sha224_hmac", CKM_SHA224_HMAC},
    {"ckm_sha256_hmac", CKM_SHA256_HMAC},
    {"ckm_sha384_hmac", CKM_SHA384_HMAC},
    {"ckm_sha512_hmac", CKM_SHA512_HMAC},
    {"ckm_sha3_224_hmac", CKM_SHA3_224_HMAC},
    {"ckm_sha3_256_hmac", CKM_SHA3_256_HMAC},
    {"ckm_sha3_384_hmac", CKM_SHA3_384_HMAC},
    {"ckm_sha3_512_hmac", CKM_SHA3_512_HMAC},

    /* SHA based HMAC algorithms with selectable output length */
    {"ckm_sha1_hmac_general", CKM_SHA_1_HMAC_GENERAL},
    {"ckm_sha224_hmac_general", CKM_SHA224_HMAC_GENERAL},
    {"ckm_sha256_hmac_general", CKM_SHA256_HMAC_GENERAL},
    {"ckm_sha384_hmac_general", CKM_SHA384_HMAC_GENERAL},
    {"ckm_sha512_hmac_general", CKM_SHA512_HMAC_GENERAL},
    {"ckm_sha3_224_hmac_general", CKM_SHA3_224_HMAC_GENERAL},
    {"ckm_sha3_256_hmac_general", CKM_SHA3_256_HMAC_GENERAL},
    {"ckm_sha3_384_hmac_general", CKM_SHA3_384_HMAC_GENERAL},
    {"ckm_sha3_512_hmac_general", CKM_SHA3_512_HMAC_GENERAL},

    /* SHA digest algorithms */
    {"ckm_sha1", CKM_SHA_1},
    {"ckm_sha224", CKM_SHA224},
    {"ckm_sha256", CKM_SHA256},
    {"ckm_sha384", CKM_SHA384},
    {"ckm_sha512", CKM_SHA512},
    {"ckm_sha3_224", CKM_SHA3_224},
    {"ckm_sha3_256", CKM_SHA3_256},
    {"ckm_sha3_384", CKM_SHA3_384},
    {"ckm_sha3_512", CKM_SHA3_512},

    /* Other algorithms */  
    {"ckm_generic_secret_key_gen", CKM_GENERIC_SECRET_KEY_GEN},

    {NULL, 0}
};

static const key_type_map_t key_type_map[] = {
    {"ckk_rsa", CKK_RSA},
    {"ckk_dsa", CKK_DSA},
    {"ckk_dh", CKK_DH},
    {"ckk_ecdsa", CKK_ECDSA},
    {"ckk_ec", CKK_EC},
    {"ckk_x9_42_dh", CKK_X9_42_DH},
    {"ckk_kea", CKK_KEA},
    {"ckk_generic_secret", CKK_GENERIC_SECRET},
    {"ckk_rc2", CKK_RC2},
    {"ckk_rc4", CKK_RC4},
    {"ckk_des", CKK_DES},
    {"ckk_des2", CKK_DES2},
    {"ckk_des3", CKK_DES3},
    {"ckk_cast", CKK_CAST},
    {"ckk_cast3", CKK_CAST3},
    {"ckk_cast5", CKK_CAST5},
    {"ckk_cast128", CKK_CAST128},
    {"ckk_rc5", CKK_RC5},
    {"ckk_idea", CKK_IDEA},
    {"ckk_skipjack", CKK_SKIPJACK},
    {"ckk_baton", CKK_BATON},
    {"ckk_juni", CKK_JUNIPER},
    {"ckk_cdmf", CKK_CDMF},
    {"ckk_aes", CKK_AES},
    {"ckk_blowfish", CKK_BLOWFISH},
    {"ckk_twofish", CKK_TWOFISH},
    {"ckk_securid", CKK_SECURID},
    {"ckk_hotp", CKK_HOTP},
    {"ckk_acti", CKK_ACTI},
    {"ckk_camellia", CKK_CAMELLIA},
    {"ckk_aria", CKK_ARIA},
    {"ckk_md5_hmac", CKK_MD5_HMAC},
    {"ckk_sha_1_hmac", CKK_SHA_1_HMAC},
    {"ckk_ripemd128_hmac", CKK_RIPEMD128_HMAC},
    {"ckk_ripemd160_hmac", CKK_RIPEMD160_HMAC},
    {"ckk_sha256_hmac", CKK_SHA256_HMAC},
    {"ckk_sha384_hmac", CKK_SHA384_HMAC},
    {"ckk_sha512_hmac", CKK_SHA512_HMAC},
    {"ckk_sha224_hmac", CKK_SHA224_HMAC},
    {"ckk_seed", CKK_SEED},
    {"ckk_gostr3410", CKK_GOSTR3410},
    {"ckk_gostr3411", CKK_GOSTR3411},
    {"ckk_gost28147", CKK_GOST28147},
    {"ckk_chacha20", CKK_CHACHA20},
    {"ckk_poly1305", CKK_POLY1305},
    {"ckk_aes_xts", CKK_AES_XTS},
    {"ckk_sha3_224_hmac", CKK_SHA3_224_HMAC},
    {"ckk_sha3_256_hmac", CKK_SHA3_256_HMAC},
    {"ckk_sha3_384_hmac", CKK_SHA3_384_HMAC},
    {"ckk_sha3_512_hmac", CKK_SHA3_512_HMAC},
    {"ckk_blake2b_160_hmac", CKK_BLAKE2B_160_HMAC},
    {"ckk_blake2b_256_hmac", CKK_BLAKE2B_256_HMAC},
    {"ckk_blake2b_384_hmac", CKK_BLAKE2B_384_HMAC},
    {"ckk_blake2b_512_hmac", CKK_BLAKE2B_512_HMAC},
    {"ckk_salsa20", CKK_SALSA20},
    {"ckk_x2ratchet", CKK_X2RATCHET},
    {"ckk_ec_edwards", CKK_EC_EDWARDS},
    {"ckk_ec_montgomery", CKK_EC_MONTGOMERY},
    {"ckk_hkdf", CKK_HKDF},
    {"ckk_sha512_224_hmac", CKK_SHA512_224_HMAC},
    {"ckk_sha512_256_hmac", CKK_SHA512_256_HMAC},
    {"ckk_sha512_t_hmac", CKK_SHA512_T_HMAC},
    {"ckk_hss", CKK_HSS},
    {"ckk_vendor_defined", CKK_VENDOR_DEFINED},
    {NULL, 0}
};

/* NIF function registration */
static ErlNifFunc nif_funcs[] = {
  {"n_load_module", 1, load_module},
  {"n_list_slots", 2, list_slots},
  {"n_token_info", 2, token_info},
  {"n_finalize", 1, finalize},
  {"n_open_session", 3, open_session},
  {"n_close_session", 2, close_session},
  {"n_close_all_sessions", 2, close_all_sessions},
  {"n_session_info", 2, session_info},
  {"n_session_login", 4, session_login},
  {"n_session_logout", 2, session_logout},
  {"n_find_objects", 4, find_objects},
  {"n_generate_key", 4, generate_key},
  {"n_get_object_attributes", 4, get_object_attributes},
  {"n_encrypt", 3, encrypt},
  {"n_encrypt_init", 4, encrypt_init},
  {"n_encrypt_update", 3, encrypt_update},
  {"n_encrypt_final", 2, encrypt_final},
  {"n_decrypt", 3, decrypt},
  {"n_decrypt_init", 4, decrypt_init},
  {"n_decrypt_update", 3, decrypt_update},
  {"n_decrypt_final", 2, decrypt_final},
  {"n_generate_random", 3, generate_random},
  {"n_destroy_object", 3, destroy_object},
  {"n_list_mechanisms", 2, list_mechanisms},
  {"n_mechanism_info", 3, mechanism_info},
  {"n_sign", 3, sign},
  {"n_sign_init", 4, sign_init},
  {"n_sign_update", 3, sign_update},
  {"n_sign_final", 2, sign_final},
  {"n_verify_init", 4, verify_init},
  {"n_verify", 4, verify},
  {"n_digest_init", 3, digest_init},
  {"n_digest_update", 3, digest_update},
  {"n_digest_final", 2, digest_final},
  {"n_digest", 3, digest},
  {"n_generate_key_pair", 5, generate_key_pair}
};

/* Implementation of load_module/1: Load a PKCS#11 module, get the function list, 
   and initialize the module. Returns a resource that holds a reference the module and. */
static ERL_NIF_TERM load_module(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    char path[1024];
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_C_GetFunctionList c_get_function_list = NULL;
    CK_FUNCTION_LIST_PTR fun_list = NULL;
    ERL_NIF_TERM error_str;
    ERL_NIF_TERM ok_term;
    ERL_NIF_TERM p11_module_term;
    void *pkcs11_lib = NULL;
    
    P11_debug("load_module: enter");
    REQUIRE_ARGS(env, argc, 1);

    secure_zero(path, sizeof(path));

    rv = enif_get_string(env, argv[0], path, sizeof(path), ERL_NIF_UTF8);
    if (rv <= 0) {
      return enif_make_tuple2(env, 
        enif_make_atom(env, "error"),
        enif_make_atom(env, "invalid_path"));
    }

    p11_module_t* p11_module_rt = 
      enif_alloc_resource(p11_module_resource_type, sizeof(p11_module_t));
    if (p11_module_rt == NULL) {
      return enif_make_tuple2(env, 
        enif_make_atom(env, "error"),
        enif_make_atom(env, "alloc_resource_failed"));
    }
    P11_debug("load_module: p11_module=%p", p11_module_rt);

    /* load the PKCS#11 module */
    P11_debug("load_module: dlopen");
    pkcs11_lib = dlopen(path, RTLD_NOW);
    
    if (!pkcs11_lib) {
      P11_debug("load_module: dlopen failed");
      enif_release_resource(p11_module_rt);
      error_str = enif_make_string(env, dlerror(), ERL_NIF_UTF8);
      return enif_make_tuple3(env, 
        enif_make_atom(env, "error"),
        enif_make_atom(env, "dlopen_failed"),
        error_str);
    }

    /* C_GetFunctionList can be called before C_Initialize */
    P11_debug("load_module: dlsym C_GetFunctionList");
    c_get_function_list = (CK_C_GetFunctionList) dlsym(pkcs11_lib, "C_GetFunctionList");
    if (!c_get_function_list) {
      char *error_cstr = dlerror();
      error_str = enif_make_string(env, error_cstr, ERL_NIF_UTF8);
      P11_debug("load_module: dlsym C_GetFunctionList failed: %s", error_cstr);
      enif_release_resource(p11_module_rt);
      return enif_make_tuple3(env, 
        enif_make_atom(env, "error"),
        enif_make_atom(env, "dlsym_failed"),
        error_str);
    }

    /* Now, actually call C_GetFunctionList */
    P11_debug("load_module: c_get_function_list");
    rv = c_get_function_list(&fun_list);
    if (rv != CKR_OK) {
      P11_debug("load_module: c_get_function_list failed");
        enif_release_resource(p11_module_rt);
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_atom(env, "get_function_list_failed"));
    }

    P11_debug("load_module: fun_list->C_Initialize");
    rv = fun_list->C_Initialize(NULL);

    if (rv != CKR_OK) {
      P11_debug("load_module: fun_list->C_Initialize failed");
      enif_release_resource(p11_module_rt);
      return P11_error(env, "C_Initialize", rv);
    }

    /* Store the module and function list in resource */
    p11_module_rt->p11_module = pkcs11_lib;
    p11_module_rt->fun_list = fun_list;
    P11_debug("load_module: p11_module->p11_module=%p", p11_module_rt->p11_module);
    P11_debug("load_module: p11_module->fun_list=%p", p11_module_rt->fun_list);
    p11_module_term = enif_make_resource(env, p11_module_rt);
    ok_term = enif_make_tuple2(env, enif_make_atom(env, "ok"), p11_module_term);

    P11_debug("load_module: return :ok");
    enif_release_resource(p11_module_rt);
    return ok_term;
}

/* Implementation of list_slots/2: List the slots of a token with C_GetSlotList. */
static ERL_NIF_TERM list_slots(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_BBOOL token_present = CK_FALSE;
    p11_module_t* p11_module = NULL;
    CK_ULONG slot_count = 0;
    CK_SLOT_ID_PTR slot_ids = NULL;
    CK_SLOT_INFO slot_info = {0};
    ERL_NIF_TERM res = enif_make_list(env, 0);

    P11_debug("list_slots: enter");
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

    /* allocate memory for the slot ids and retrieve them */
    slot_ids = (CK_SLOT_ID_PTR) calloc(slot_count, sizeof(CK_SLOT_ID));
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
        /* slotDescription and manufacturedID have a fixed length of 64 bytes and are padded. */
        p11str_to_term(env, slot_info.slotDescription, sizeof(slot_info.slotDescription)),
        p11str_to_term(env, slot_info.manufacturerID, sizeof(slot_info.manufacturerID)),
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

  CK_RV rv = CKR_GENERAL_ERROR;
  CK_ULONG slot_id = 0;
  CK_TOKEN_INFO token_info = {0};
  p11_module_t* p11_module = NULL;
  ERL_NIF_TERM map = enif_make_new_map(env);

  P11_debug("token_info: enter");
  REQUIRE_ARGS(env, argc, 2);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  ULONG_ARG(env, argv[1], slot_id);

  P11_call(rv, p11_module, C_GetTokenInfo, slot_id, &token_info);
  if (rv != CKR_OK) {
    return P11_error(env, "C_GetTokenInfo", rv);
  }

  /* The strings in this struct have a fixed lengths and are padded. 
     No NULL terminator is present. */
  enif_make_map_put(env, map, 
    enif_make_atom(env, "label"), 
    p11str_to_term(env, token_info.label, sizeof(token_info.label)), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "manufacturer_id"), 
    p11str_to_term(env, token_info.manufacturerID, sizeof(token_info.manufacturerID)), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "model"), 
    p11str_to_term(env, token_info.model, sizeof(token_info.model)), &map);

  enif_make_map_put(env, map, 
    enif_make_atom(env, "serial_number"), 
    p11str_to_term(env, token_info.serialNumber, sizeof(token_info.serialNumber)), &map);

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
    p11str_to_term(env, token_info.utcTime, sizeof(token_info.utcTime)), &map);

  return enif_make_tuple2(env, enif_make_atom(env, "ok"), map);
}

static ERL_NIF_TERM finalize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;

  P11_debug("finalize: enter");
  REQUIRE_ARGS(env, argc, 1);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  P11_call(rv, p11_module, C_Finalize, NULL);
  if (rv != CKR_OK) {
    return P11_error(env, "C_Finalize", rv);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM open_session(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  CK_ULONG slot_id = 0;
  CK_FLAGS flags = 0;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;

  P11_debug("open_session: enter");
  REQUIRE_ARGS(env, argc, 3);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  ULONG_ARG(env, argv[1], slot_id);
  ULONG_ARG(env, argv[2], flags);

  /* According to the PKCS#11 spec, the flag CKF_SERIAL_SESSION must
     always be set. */
  P11_call(rv, p11_module, C_OpenSession, slot_id, CKF_SERIAL_SESSION | flags, NULL, NULL, &session_handle);
  if (rv != CKR_OK) {
    return P11_error(env, "C_OpenSession", rv);
  }

  if (P11_DEBUG) {
    fprintf(stderr, "P11_session_debug: new session_handle=%lu", session_handle);
  }
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_ulong(env, session_handle));
}

static ERL_NIF_TERM close_session(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;

  P11_debug("close_session: enter");
  REQUIRE_ARGS(env, argc, 2);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  ULONG_ARG(env, argv[1], session_handle);

  P11_call(rv, p11_module, C_CloseSession, session_handle);
  if (rv != CKR_OK) {
    return P11_error(env, "C_CloseSession", rv);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM close_all_sessions(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;

  P11_debug("close_all_sessions: enter");
  REQUIRE_ARGS(env, argc, 2);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  ULONG_ARG(env, argv[1], session_handle);

  P11_call(rv, p11_module, C_CloseAllSessions, session_handle);
  if (rv != CKR_OK) {
    return P11_error(env, "C_CloseAllSessions", rv);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM session_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_SESSION_INFO session_info = {0};
  ERL_NIF_TERM result;

  P11_debug("session_info: enter");
  REQUIRE_ARGS(env, argc, 2);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  ULONG_ARG(env, argv[1], session_handle);

  P11_call(rv, p11_module, C_GetSessionInfo, session_handle, &session_info);
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

  CK_RV rv = CKR_GENERAL_ERROR;
  CK_SESSION_HANDLE session_handle = 0;
  p11_module_t* p11_module = NULL;
  CK_USER_TYPE user_type = 0;
  char pin[MAX_PIN_LENGTH];
  size_t pin_length = 0;
  char *copy_pin = NULL;

  P11_debug("session_login: enter");
  REQUIRE_ARGS(env, argc, 4);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  ULONG_ARG(env, argv[1], session_handle);
  ULONG_ARG(env, argv[2], user_type);

  secure_zero(pin, sizeof(pin));
  pin_length = enif_get_string(env, argv[3], pin, MAX_PIN_LENGTH, ERL_NIF_UTF8);
  if (pin_length <= 0) {
    return enif_make_badarg(env);
  }
  pin_length--; /* enif_get_string includes the null terminator */

  copy_pin = (char *) calloc(pin_length + 1, sizeof(char));
  if (copy_pin == NULL) {
    return enif_make_tuple2(env, 
              enif_make_atom(env, "error"), 
              enif_make_atom(env, "memory_allocation_failed"));
  }
  memcpy(copy_pin, pin, pin_length);
  
  P11_call(rv, p11_module, C_Login, session_handle, 
           user_type, (CK_UTF8CHAR_PTR) copy_pin, (CK_ULONG) pin_length);

  free(copy_pin);
  if (rv != CKR_OK) {
    return P11_error(env, "C_Login", rv);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM session_logout(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  CK_SESSION_HANDLE session_handle = 0;
  p11_module_t* p11_module = NULL;

  P11_debug("session_logout: enter");
  REQUIRE_ARGS(env, argc, 2);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  } 

  ULONG_ARG(env, argv[1], session_handle);

  P11_call(rv, p11_module, C_Logout, session_handle);
  if (rv != CKR_OK) {
    return P11_error(env, "C_Logout", rv);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM generate_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_OBJECT_HANDLE key_handle = 0;
  CK_ATTRIBUTE_PTR attribute_list = NULL;
  CK_ULONG attribute_count = 0;
  ERL_NIF_TERM conversion_result;
  CK_MECHANISM mechanism = {0};
  ERL_NIF_TERM mech_conversion_result;

  P11_debug("generate_key: enter");
  REQUIRE_ARGS(env, argc, 4);

  /* argv[0]: PKCS#11 module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: mechanism as a tuple */
  if (!enif_is_tuple(env, argv[2])) {
    return enif_make_badarg(env);
  }

   /* argv[4]: attributes as list of tuples */
  if (!enif_is_list(env, argv[3])) {
    return enif_make_badarg(env);
  }

  P11_debug("generate_key: module=%p, session=%lu", p11_module, session_handle);
  
  mech_conversion_result = term_to_mechanism(env, argv[2], &mechanism);
  P11_debug("generate_key: mech_conversion_result=%T", mech_conversion_result);
  if (enif_compare(mech_conversion_result, enif_make_atom(env, "ok")) != 0) {
    return mech_conversion_result;
  }
  P11_debug("generate_key: converted mechanism %p", &mechanism);
  P11_debug_mechanism(&mechanism);
  
  /* convert attributes to template */
  conversion_result = term_to_attributes(env, argv[3], &attribute_list, &attribute_count);
  if (enif_compare(conversion_result, enif_make_atom(env, "ok")) != 0) {
    return conversion_result;
  }
  P11_debug("generate_key: converted attributes");
  
  P11_debug("generate_key: mechanism=%p attribute_list=%p attribute_count=%d", 
    &mechanism, attribute_list, attribute_count);
  P11_call(rv, p11_module, C_GenerateKey, session_handle, &mechanism,
      attribute_list, attribute_count, &key_handle);

  if (rv != CKR_OK) {
    free(attribute_list[0].pValue); /* frees the value buffer */
    free(attribute_list);
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    return P11_error(env, "C_GenerateKey", rv);
  }

  free(attribute_list[0].pValue); /* frees the value buffer */
  free(attribute_list);
  if (mechanism.pParameter != NULL) {
    free(mechanism.pParameter);
  }

  P11_debug("generate_key: key_handle=%lu", key_handle);
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_ulong(env, key_handle));
}

static ERL_NIF_TERM find_objects(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ERL_NIF_TERM conversion_result;
  CK_ULONG max_hits = 0;
  CK_ULONG hit_count = 0;
  CK_ATTRIBUTE_PTR attribute_list = NULL;
  CK_ULONG attribute_count = 0;
  CK_OBJECT_HANDLE_PTR object_list = NULL;

  P11_debug("find_objects: enter");
  REQUIRE_ARGS(env, argc, 4);

  /* argv[0]: PKCS#11 module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: attributes as list of tuples */
  if (!enif_is_list(env, argv[2])) {
    return enif_make_badarg(env);
  }

  /* argv[3]: max hits */
  ULONG_ARG(env, argv[3], max_hits);
  max_hits = max_hits > FIND_OBJ_MAX_HITS ? FIND_OBJ_MAX_HITS : max_hits;

  object_list = (CK_OBJECT_HANDLE_PTR) calloc(max_hits, sizeof(CK_OBJECT_HANDLE));
  if (object_list == NULL) {
    return enif_make_tuple2(env, 
              enif_make_atom(env, "error"), 
              enif_make_atom(env, "memory_allocation_failed"));
  }
  P11_debug("find_objects: allocated object_list=%p len=%lu", object_list, max_hits);

  /* convert attributes to template */
  conversion_result = term_to_attributes(env, argv[2], &attribute_list, &attribute_count);
  if (enif_compare(conversion_result, enif_make_atom(env, "ok")) != 0) {
    return conversion_result;
  }
  P11_debug("find_objects: converted %lu attributes", attribute_count);

  P11_call(rv, p11_module, C_FindObjectsInit, session_handle, attribute_list, attribute_count);

  if (rv != CKR_OK) {
    free(attribute_list[0].pValue);
    free(attribute_list);
    return P11_error(env, "C_FindObjectsInit", rv);
  }

  /* get objects */
  P11_call(rv, p11_module, C_FindObjects, session_handle, object_list, max_hits, &hit_count);
  if (rv != CKR_OK) {
    free(attribute_list[0].pValue);
    free(attribute_list);
    return P11_error(env, "C_FindObjects", rv);
  }
  P11_debug("find_objects: found %lu objects", hit_count);

  /* finish search */
  P11_call(rv, p11_module, C_FindObjectsFinal, session_handle);

  free(attribute_list[0].pValue);
  free(attribute_list);

  ERL_NIF_TERM result = enif_make_list(env, 0);
  for (int i = 0; i < hit_count; i++) {
    ERL_NIF_TERM object_handle = enif_make_ulong(env, object_list[i]);
    result = enif_make_list_cell(env, object_handle, result);
  }
  free(object_list);

  return enif_make_tuple2(env, enif_make_atom(env, "ok"), result);
}

static ERL_NIF_TERM term_to_attrib_template(
  ErlNifEnv* env, ERL_NIF_TERM term_list,
  CK_ATTRIBUTE_PTR* out_attribute_list,
  CK_ULONG_PTR out_attribute_count) {

  unsigned list_length = 0;
  unsigned attribute_index = 0;
  ERL_NIF_TERM head, tail, current_list;
  CK_ATTRIBUTE* attributes = NULL;
  CK_ATTRIBUTE_TYPE attribute_type;
  char attribute_name[MAX_ATTRIBUTE_NAME_LENGTH];
  attribute_info_t* attr_info = NULL;

  P11_debug("term_to_attrib_template: enter");
  P11_debug("term_to_attrib_template: term_list=%T", term_list);

  if (!enif_is_list(env, term_list)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_list_length(env, term_list, &list_length)) {
    return enif_make_badarg(env);
  }
  P11_debug("term_to_attrib_template: list_length=%lu", list_length);

  secure_zero(attribute_name, sizeof(attribute_name));
  attributes = (CK_ATTRIBUTE_PTR) calloc(sizeof(CK_ATTRIBUTE), list_length);
  if (attributes == NULL) {
    return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));
  }
  P11_debug("term_to_attrib_template: allocated attributes=%p len=%lu", attributes, list_length);

  current_list = term_list;
  attribute_index = 0;
  while (enif_get_list_cell(env, current_list, &head, &tail)) {

    P11_debug("term_to_attrib_template: processing element %T", head);

    if (enif_is_number(env, head)) {
      if (!enif_get_ulong(env, head, &attribute_type)) {
        free(attributes);
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_attribute_id"),
          head);
      }
      attributes[attribute_index].type = attribute_type;
    } else if (enif_is_atom(env, head)) {
      if (enif_get_atom(env, head, attribute_name, sizeof(attribute_name), ERL_NIF_UTF8) <= 0) {
        free(attributes);
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_attribute_name"),
          head);
      }
      attr_info = find_attribute_info_by_name(attribute_name);
      if (attr_info == NULL) {
        free(attributes);
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "unknown_attribute"),
          head);
      }
      attributes[attribute_index].type = attr_info->id;
    } else {
      free(attributes);
      return enif_make_tuple3(env, 
        enif_make_atom(env, "error"), 
        enif_make_atom(env, "invalid_attribute"),
        head);
    }
    attributes[attribute_index].pValue = NULL;
    attributes[attribute_index].ulValueLen = 0;
    attribute_index++;
    current_list = tail;
  }

  *out_attribute_list = attributes;
  *out_attribute_count = list_length;

  P11_debug("term_to_attrib_template: returning ok");
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM get_object_attributes(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  CK_ATTRIBUTE_PTR templates = NULL;
  CK_ULONG template_count = 0;
  ERL_NIF_TERM prep_result, attr_list;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_OBJECT_HANDLE object_handle = 0;

  P11_debug("get_object_attributes: enter");
  REQUIRE_ARGS(env, argc, 4);

  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  ULONG_ARG(env, argv[1], session_handle);
  ULONG_ARG(env, argv[2], object_handle);

  P11_debug("get_object_attributes: argv[3]=%T", argv[3]);
  prep_result = term_to_attrib_template(env, argv[3], &templates, &template_count);

  if (enif_compare(prep_result, enif_make_atom(env, "ok")) != 0) {
    return prep_result;
  }

  P11_call(rv, p11_module, C_GetAttributeValue, session_handle, object_handle, templates, template_count);
  if (rv != CKR_OK) {
    free(templates);
    return P11_error(env, "C_GetAttributeValue", rv);
  }

  for (int i = 0; i < template_count; i++) {
    if (templates[i].ulValueLen != (CK_ULONG) -1) {
      templates[i].pValue = (CK_VOID_PTR) malloc(templates[i].ulValueLen);
      if (templates[i].pValue == NULL) {
        for (int j = 0; j < i; j++) {
          if (templates[j].pValue != NULL) {
            free(templates[j].pValue);
          }
        }
        free(templates);
        return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));
      }
    }
  }

  P11_call(rv, p11_module, C_GetAttributeValue, session_handle, object_handle, templates, template_count);
  if (rv != CKR_OK) { 
    for (int i = 0; i < template_count; i++) {
      if (templates[i].pValue != NULL) {
        free(templates[i].pValue);
      }
    }
    free(templates);
    return P11_error(env, "C_GetAttributeValue", rv);
  }

  attr_list = enif_make_list(env, 0);
  for (int i = 0; i < template_count; i++) {
    ERL_NIF_TERM t = attribute_to_term(env, &templates[i]);
    attr_list = enif_make_list_cell(env, t, attr_list);
  }

  for (int i = 0; i < template_count; i++) {
    if (templates[i].pValue != NULL) {
      free(templates[i].pValue);
    }
  }
  free(templates);
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), attr_list);
}



/* NIF module callbacks */
static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
    const char* mod_name = "P11exLib";
    int flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;

    P11_debug("NIF load: enter");

    p11_module_resource_type = 
      enif_open_resource_type(env, NULL, mod_name, resource_cleanup, flags, NULL);

    if (p11_module_resource_type == NULL) {
      return -1;
    }

    P11_debug("NIF load: success");
    return 0;
}

static void unload(ErlNifEnv* caller_env, void* priv_data) {

  /* TODO: Check if we need to free the module */
  P11_debug("unload: (not doing anything)");
}

ERL_NIF_INIT(Elixir.P11ex.Lib, nif_funcs, load, NULL, NULL, unload)

/* helper functions */

static ERL_NIF_TERM p11str_to_term(ErlNifEnv *env, CK_UTF8CHAR_PTR utf8_array, size_t length) {

    ERL_NIF_TERM res_term;
    char* str = NULL;

    str = malloc(length + 1);
    if (str == NULL) {
      return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));
    }

    memcpy(str, utf8_array, length);
    str[length] = '\0';

    res_term = enif_make_string(env, str, ERL_NIF_UTF8);
    free(str);
    return res_term;
}

static ERL_NIF_TERM term_to_attributes(
  ErlNifEnv* env, ERL_NIF_TERM term_list,
  CK_ATTRIBUTE** out_attribute_list,
  CK_ULONG_PTR out_attribute_count) {

  ERL_NIF_TERM mem_error_term;
  ERL_NIF_TERM head, tail, current_list;
  unsigned list_length = 0;
  unsigned all_values_copied = 0;
  unsigned resize_needed = 0;
  unsigned value_buffer_size = 0;
  unsigned growth_factor = 0;
  attribute_info_t* attr_info = NULL;
  CK_ATTRIBUTE* attributes = NULL;
  void* value_buffer = NULL;

  P11_debug("term_to_attributes: enter");
  P11_debug("term_to_attributes: term_list=%T", term_list);

  if (!enif_is_list(env, term_list)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_list_length(env, term_list, &list_length)) {
    /* somehow it's not a proper list */
    return enif_make_badarg(env);
  }
  P11_debug("term_to_attributes: list_length=%lu", list_length);

  mem_error_term = 
      enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));

  all_values_copied = 0;
  growth_factor = 1; 
  while (!all_values_copied) {
    unsigned value_index, attr_index, space_left;

    /* This is the "template" structure of attributes that we pass to the PKCS#11 module.*/
    attributes = (CK_ATTRIBUTE_PTR) calloc(sizeof(CK_ATTRIBUTE), list_length);
    P11_debug("term_to_attributes: allocated attribute_list=%p len=%lu", attributes, list_length);

    /* allocate an array of values */
    value_buffer_size = growth_factor * ATTRIBUTE_BUFFER_SIZE;
    value_buffer = (CK_VOID_PTR_PTR) malloc(value_buffer_size);
    if (value_buffer == NULL) {
      return mem_error_term;
    }
    P11_debug("term_to_attributes: allocated value_buffer=%p size=%d", value_buffer, value_buffer_size);
    secure_zero(value_buffer, value_buffer_size);
  
    space_left = value_buffer_size;
    current_list = term_list;
    attr_index = 0;
    value_index = 0;
    resize_needed = 0;

    P11_debug("term_to_attributes: starting attribute copy loop");
    while (!resize_needed && enif_get_list_cell(env, current_list, &head, &tail)) {
      char attribute_name[MAX_ATTRIBUTE_NAME_LENGTH];
      int attribute_name_length, num_elements;
      unsigned long attribute_id;
      unsigned value_size;
      const ERL_NIF_TERM* elements;

      P11_debug("term_to_attributes: processing element %T", head);

      /* each element in the list must be a tuple of the form {atom, value} or {ulong, binary} */
      if (!(enif_is_tuple(env, head) && enif_get_tuple(env, head, &num_elements, &elements))) {
        P11_debug("term_to_attributes: invalid attribute tuple, case 1");
        free(attributes);
        free(value_buffer);
        return enif_make_tuple3(env, 
            enif_make_atom(env, "error"), 
            enif_make_atom(env, "invalid_attribute_tuple"),
            head);
      }
      if (num_elements != 2) {
        P11_debug("term_to_attributes: invalid attribute tuple, case 2");
        free(attributes);
        free(value_buffer);
        return enif_make_tuple3(env, 
            enif_make_atom(env, "error"), 
            enif_make_atom(env, "invalid_attribute_tuple"),
            head);
      }

      /* lookup attribute info */ 
      if (enif_is_atom(env, elements[0])) {
        attribute_name_length = enif_get_atom(env, elements[0], attribute_name, sizeof(attribute_name), ERL_NIF_UTF8);
        if (attribute_name_length <= 0) {
          free(attributes);
          free(value_buffer);
          return enif_make_tuple3(env, 
            enif_make_atom(env, "error"), 
            enif_make_atom(env, "invalid_attribute_name"),
            elements[0]);
        }
        attr_info = find_attribute_info_by_name(attribute_name);
      } else if (enif_is_number(env, elements[0])) {
        if (!enif_get_ulong(env, elements[0], &attribute_id)) {
          free(attributes);
          free(value_buffer);
          return enif_make_badarg(env);
        }
        attr_info = find_attribute_info_by_id(attribute_id);
        if (attr_info == NULL) {
          free(attributes);
          free(value_buffer);
          return enif_make_tuple3(env, 
            enif_make_atom(env, "error"), 
            enif_make_atom(env, "unknown_attribute"),
            elements[0]);
        }
      }

      if (attr_info == NULL) {
        free(attributes);
        free(value_buffer);
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "unknown_attribute"),
          elements[0]);
      }

      value_size = copy_attribute_value(
              env, elements[1], attr_info, 
              &(value_buffer[value_index]), space_left);
      P11_debug("copy_attribute_value: r=%d", value_size);

      if (value_size == -1) {
        /* value was not copied, because of lack of space */
        resize_needed = 1;
      } else if (value_size == -2) {
        free(attributes);
        free(value_buffer);
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_attribute_value"),
          elements[0]);
      } else if (value_size == -3) {
        free(attributes);
        free(value_buffer);
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "unsupported_attribute_type"),
          elements[0]);
      } else {
        P11_debug("term_to_attributes: copied attribute index=%d", attr_index);
        attributes[attr_index].pValue = &(value_buffer[value_index]);
        attributes[attr_index].ulValueLen = value_size;
        attributes[attr_index].type = attr_info->id;
        P11_debug_attribute(&(attributes[attr_index]));

        value_index += value_size;
        space_left -= value_size;
        attr_index++;
        current_list = tail;
      }
    }

    if (resize_needed) {      
      free(value_buffer);
      growth_factor++;
      value_buffer_size = growth_factor * ATTRIBUTE_BUFFER_SIZE;
      value_buffer = (CK_VOID_PTR_PTR) malloc(value_buffer_size);
      if (value_buffer == NULL) {
        return mem_error_term;
      }
      space_left = value_buffer_size;
    } else {
      all_values_copied = 1;
    }
    P11_debug_buffer(value_buffer, MIN(value_buffer_size, value_index));
  }

  *out_attribute_list = attributes;
  *out_attribute_count = list_length;

  return enif_make_atom(env, "ok");
}

/* Return 0 on success, negative value on error */
static ERL_NIF_TERM term_to_mechanism(ErlNifEnv* env, ERL_NIF_TERM term, CK_MECHANISM_PTR mechanism) {

  int num_elements = 0, mech_type_result = 0;
  ERL_NIF_TERM param_conv_result;
  const ERL_NIF_TERM* elements = NULL;
  CK_MECHANISM_TYPE mechanism_type = 0;

  P11_debug("term_to_mechanism: enter");

  if (!enif_is_tuple(env, term)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "invalid_mechanism_tuple"));
  }
  
  if (!enif_get_tuple(env, term, &num_elements, &elements)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "invalid_mechanism_tuple"));
  }

  if (!(num_elements == 1 || num_elements == 2)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "invalid_mechanism_tuple"));
  }

  mech_type_result = mechanism_type_from_term(env, elements[0], &mechanism_type);
  P11_debug("term_to_mechanism: type conversion res=%d type=0x%lx num_elems=%d", 
    mech_type_result, mechanism_type, num_elements);
  if (mech_type_result < 0) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "invalid_mechanism_type"));
  } 

  mechanism->mechanism = mechanism_type;
  mechanism->pParameter = NULL;
  mechanism->ulParameterLen = 0;

  if (num_elements == 2) {
    if (enif_is_map(env, elements[1])) {
      param_conv_result = set_mechanism_parameters_from_term(env, 
        elements[0], elements[1], mechanism_type, mechanism);
      P11_debug("term_to_mechanism: param conversion res=%T", param_conv_result);
      if (enif_compare(param_conv_result, enif_make_atom(env, "ok")) != 0) {
        return param_conv_result;
      }
    } else {
      return enif_make_tuple3(env, 
        enif_make_atom(env, "error"), 
        enif_make_atom(env, "invalid_mechanism_parameter"),
        elements[1]);
    }
  }

  P11_debug("term_to_mechanism: exit");
  return enif_make_atom(env, "ok");
}

/* Translate the mechanism type to an atom. */
static ERL_NIF_TERM ckm_to_atom(ErlNifEnv* env, CK_MECHANISM_TYPE ckm) {

  /* Search through the mechanism map for a matching value */
  for (const mechanism_map_t *m = mechanism_map; m->name != NULL; m++) {
    if (m->value == ckm) {
      return enif_make_atom(env, m->name);
    }
  }
  
  /* If not found, return the value as an unsigned long */
  return enif_make_ulong(env, (unsigned long)ckm);
}

/* Translate the mechanism parameters from a term to a mechanism structure.
   Returns an atom with the result of the operation (:ok or {:error, reason})
 */
static ERL_NIF_TERM set_mechanism_parameters_from_term(ErlNifEnv* env, 
  ERL_NIF_TERM mech_name_term, ERL_NIF_TERM map, 
  CK_MECHANISM_TYPE mech_type, CK_MECHANISM_PTR mechanism) {

  P11_debug("set_mechanism_parameters_from_term: enter, mech_name_term=%T, map=%T", mech_name_term, map);
  switch(mech_type) {

    case CKM_AES_ECB:
    case CKM_AES_KEY_WRAP:
    case CKM_AES_KEY_WRAP_PAD:
    case CKM_AES_MAC:
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
      /* This mechanism has no parameters */
      return enif_make_atom(env, "ok");
      break;

    case CKM_AES_GCM: {
      ErlNifBinary iv_binary, aad_binary;
      size_t param_size = 0;
      CK_GCM_PARAMS *params = NULL;
      CK_BYTE_PTR iv_ptr = NULL, aad_ptr = NULL;
      CK_ULONG tag_bits = 0;
      ERL_NIF_TERM tag_bits_term, iv_term, aad_term;

      if (enif_get_map_value(env, map, enif_make_atom(env, "iv"), &iv_term)
          && enif_is_binary(env, iv_term)) {
        enif_inspect_binary(env, iv_term, &iv_binary);
      } else {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_iv_parameter"), iv_term);
      }

      if (enif_get_map_value(env, map, enif_make_atom(env, "aad"), &aad_term)) {
        if (enif_is_binary(env, aad_term)) {
          enif_inspect_binary(env, aad_term, &aad_binary);
        } else {
          return enif_make_tuple3(env, enif_make_atom(env, "error"), 
            enif_make_atom(env, "invalid_aad_parameter"), aad_term);
        }
      }

      if (!(enif_get_map_value(env, map, enif_make_atom(env, "tag_bits"), &tag_bits_term)
          && enif_get_ulong(env, tag_bits_term, &tag_bits))) {
        return enif_make_tuple3(env, enif_make_atom(env, "error"), 
                enif_make_atom(env, "invalid_tag_bits_parameter"), tag_bits_term);
      }

      P11_debug("set_mechanism_parameters_from_term: CKM_AES_GCM iv_len=%x, aad_len=%x",
        iv_binary.size, aad_binary.size);
      /* The parameters for this mechanism are represented as a struct.
         We allocate memory for the struct, fill it, and set the pointer
         in the mechanism structure to this struct. Directly after the parameter 
         struct, we allocate memory for the iv and aad. */
      param_size = sizeof(CK_GCM_PARAMS) + iv_binary.size + aad_binary.size;
      params = (CK_GCM_PARAMS*) calloc(1, param_size);
      if (params == NULL) {
        return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));
      }
      
      iv_ptr = (CK_BYTE_PTR) ((CK_BYTE_PTR)params + sizeof(CK_GCM_PARAMS));
      aad_ptr = (CK_BYTE_PTR) (iv_ptr + iv_binary.size);
      memcpy(iv_ptr, iv_binary.data, iv_binary.size);
      memcpy(aad_ptr, aad_binary.data, aad_binary.size);

      params->pIv = iv_ptr;
      params->ulIvLen = iv_binary.size;
      params->ulIvBits = 0;

      params->pAAD = aad_ptr;
      params->ulAADLen = aad_binary.size;
      params->ulTagBits = tag_bits;

      mechanism->pParameter = params;
      mechanism->ulParameterLen = sizeof(CK_GCM_PARAMS);
      P11_debug("set_mechanism_parameters_from_term: CKM_AES_GCM params=%p, iv_ptr=%p, iv_len=%x, aad_ptr=%p, aad_len=%x, tag_bits=%d", 
        params, iv_ptr, iv_binary.size, aad_ptr, aad_binary.size, tag_bits);
      #ifdef P11_DEBUG
        print_buffer(params, param_size);
      break;
      #endif
    }

    case CKM_AES_OFB:
    case CKM_AES_CBC: {
      ErlNifBinary iv_binary;
      ERL_NIF_TERM iv_term;
      CK_BYTE_PTR params = NULL;
      size_t param_size = 16; /* size of one AES block / iv length */

      P11_debug("set_mechanism_parameters_from_term: CKM_AES_OFB/CKM_AES_CBC enter, map=%T", map);

      if (enif_get_map_value(env, map, enif_make_atom(env, "iv"), &iv_term)
          && enif_is_binary(env, iv_term)) {
        P11_debug("set_mechanism_parameters_from_term: OFB/CBC iv_term=%T", iv_term);
        enif_inspect_binary(env, iv_term, &iv_binary);
        P11_debug("set_mechanism_parameters_from_term: iv_binary.size=%d", iv_binary.size);
        if (iv_binary.size != param_size) {
          return enif_make_tuple3(env, 
            enif_make_atom(env, "error"), 
            enif_make_atom(env, "invalid_iv_parameter"), iv_term);
        }
      } else {
        return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_iv_parameter"));
      }

      /* There's no struct for the parameters of this mechanism. It's
         just a byte array. */
      params = (CK_BYTE_PTR) calloc(1, param_size);
      if (params == NULL) {
        return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));
      }

      memcpy(params, iv_binary.data, param_size);
      mechanism->pParameter = params;
      mechanism->ulParameterLen = param_size;
      break;
    }

    case CKM_AES_CTR: {
      ErlNifBinary iv_binary;
      ERL_NIF_TERM iv_term, counter_bits_term;
      CK_ULONG counter_bits = 0;
      CK_AES_CTR_PARAMS *params = NULL;

      if (enif_get_map_value(env, map, enif_make_atom(env, "iv"), &iv_term)
          && enif_is_binary(env, iv_term)) {
        enif_inspect_binary(env, iv_term, &iv_binary);
        if (iv_binary.size != 16) {
          return enif_make_tuple3(env, 
            enif_make_atom(env, "error"), 
            enif_make_atom(env, "invalid_iv_parameter"), iv_term);
        }
      } else {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_iv_parameter"), map);
      }

      if (!(enif_get_map_value(env, map, enif_make_atom(env, "counter_bits"), &counter_bits_term)
          && enif_get_ulong(env, counter_bits_term, &counter_bits)
          && counter_bits <= 128
          && counter_bits % 8 == 0)) {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_counter_bits_parameter"), map);
      }
      P11_debug("set_mechanism_parameters_from_term: CKM_AES_CTR counter_bits=%d", counter_bits);

      /* The parameters for this mechanism are represented as a struct.
         We allocate memory for the struct, fill it, and set the pointer
         in the mechanism structure to the struct. */
      params = (CK_AES_CTR_PARAMS*) calloc(1, sizeof(CK_AES_CTR_PARAMS));
      if (params == NULL) {
        return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));
      }
    
      memcpy(params->cb, iv_binary.data, sizeof(params->cb));
      params->ulCounterBits = counter_bits;
      
      mechanism->pParameter = params;
      mechanism->ulParameterLen = sizeof(CK_AES_CTR_PARAMS);

      break;
    }

    case CKM_AES_CCM: {
      ErlNifBinary nonce_binary, aad_binary;
      ERL_NIF_TERM nonce_term, aad_term, data_len_term, mac_len_term;
      CK_CCM_PARAMS *params = NULL;
      CK_ULONG data_len = 0, mac_len = 0;
      size_t param_size = 0;

      if (enif_get_map_value(env, map, enif_make_atom(env, "nonce"), &nonce_term)
          && enif_is_binary(env, nonce_term)) {
        enif_inspect_binary(env, nonce_term, &nonce_binary);
      } else {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_nonce_parameter"), nonce_term);
      }

      if (enif_get_map_value(env, map, enif_make_atom(env, "aad"), &aad_term)
          && enif_is_binary(env, aad_term)) {
        enif_inspect_binary(env, aad_term, &aad_binary);
      } else {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_aad_parameter"), aad_term);
      }

      if (enif_get_map_value(env, map, enif_make_atom(env, "data_len"), &data_len_term)
          && enif_get_ulong(env, data_len_term, &data_len)) {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_data_len_parameter"), data_len_term);
      }

      if (enif_get_map_value(env, map, enif_make_atom(env, "mac_len"), &mac_len_term)
          && enif_get_ulong(env, mac_len_term, &mac_len)) {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_mac_len_parameter"), mac_len_term);
      }
      
      param_size = sizeof(CK_CCM_PARAMS) + nonce_binary.size + aad_binary.size;
      params = (CK_CCM_PARAMS*) calloc(1, param_size);
      if (params == NULL) {
        return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));
      }
      
      memcpy(params->pNonce, nonce_binary.data, nonce_binary.size);
      params->ulNonceLen = nonce_binary.size;

      memcpy(params->pAAD, aad_binary.data, aad_binary.size);
      params->ulAADLen = aad_binary.size;

      params->ulDataLen = data_len;
      params->ulMACLen = mac_len;

      mechanism->pParameter = params;
      mechanism->ulParameterLen = param_size;

      break;
    }

    case CKM_AES_CMAC_GENERAL: {
      ERL_NIF_TERM mac_len_term;
      CK_ULONG mac_len = 0;
      CK_ULONG_PTR params = NULL;

      if (!enif_get_map_value(env, map, enif_make_atom(env, "mac_len"), &mac_len_term)
          || !enif_get_ulong(env, mac_len_term, &mac_len)) {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_mac_len_parameter"), mac_len_term);
      }
      
      params = (CK_ULONG_PTR) calloc(1, sizeof(CK_ULONG));
      if (params == NULL) {
        return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));
      }

      *params = mac_len;
      mechanism->pParameter = params;
      mechanism->ulParameterLen = sizeof(CK_ULONG);

      break;
    }

    case CKM_RSA_PKCS_PSS: {
      ERL_NIF_TERM salt_len_term, hash_alg_term, mgf_hash_alg_term;
      CK_ULONG salt_len = 32;
      CK_RSA_PKCS_PSS_PARAMS *params = NULL;

      if (!enif_get_map_value(env, map, enif_make_atom(env, "salt_len"), &salt_len_term)
          || !enif_get_ulong(env, salt_len_term, &salt_len) 
          || salt_len < 16 
          || salt_len > 256) {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_salt_len_parameter"), salt_len_term);
      }

      params = (CK_RSA_PKCS_PSS_PARAMS*) calloc(1, sizeof(CK_RSA_PKCS_PSS_PARAMS));
      if (params == NULL) {
        return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));
      }

      if (!enif_get_map_value(env, map, enif_make_atom(env, "hash_alg"), &hash_alg_term)
          || !enif_is_atom(env, hash_alg_term)) {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_hash_alg_parameter"), hash_alg_term);
      }
      params->sLen = salt_len;

      if (hash_alg_term == enif_make_atom(env, "sha")) {
        params->hashAlg = CKM_SHA_1;
      } else if (hash_alg_term == enif_make_atom(env, "sha224")) {
        params->hashAlg = CKM_SHA224;
      } else if (hash_alg_term == enif_make_atom(env, "sha256")) {
        params->hashAlg = CKM_SHA256;
      } else if (hash_alg_term == enif_make_atom(env, "sha384")) {  
        params->hashAlg = CKM_SHA384;
      } else if (hash_alg_term == enif_make_atom(env, "sha512")) {
        params->hashAlg = CKM_SHA512;
      } else {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_hash_alg_parameter"), hash_alg_term);
      }
      
      if (!enif_get_map_value(env, map, enif_make_atom(env, "mgf_hash_alg"), &mgf_hash_alg_term)
          || !enif_is_atom(env, mgf_hash_alg_term)) {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_mgf_hash_alg_parameter"), mgf_hash_alg_term);
      }

      if (mgf_hash_alg_term == enif_make_atom(env, "sha")) {
        params->mgf = CKG_MGF1_SHA1;
      } else if (mgf_hash_alg_term == enif_make_atom(env, "sha224")) {
        params->mgf = CKG_MGF1_SHA224;
      } else if (mgf_hash_alg_term == enif_make_atom(env, "sha256")) {
        params->mgf = CKG_MGF1_SHA256;
      } else if (mgf_hash_alg_term == enif_make_atom(env, "sha384")) {
        params->mgf = CKG_MGF1_SHA384;
      } else if (mgf_hash_alg_term == enif_make_atom(env, "sha512")) {
        params->mgf = CKG_MGF1_SHA512;
      } else {
        return enif_make_tuple3(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "invalid_mgf_hash_alg_parameter"), mgf_hash_alg_term);
      }

      P11_debug("set_mechanism_parameters_from_term: CKM_RSA_PKCS_PSS params=%p", params);
      P11_debug("set_mechanism_parameters_from_term: CKM_RSA_PKCS_PSS params->sLen=%lu", params->sLen);
      P11_debug("set_mechanism_parameters_from_term: CKM_RSA_PKCS_PSS params->hashAlg=0x%lx", params->hashAlg);
      P11_debug("set_mechanism_parameters_from_term: CKM_RSA_PKCS_PSS params->mgf=0x%lx", params->mgf);

      mechanism->pParameter = params;
      mechanism->ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);

      break;
    }
    
    default:
      return enif_make_tuple2(
        env,
        enif_make_atom(env, "error"),
        enif_make_atom(env, "unsupported_mechanism_type"));
      break;
  }

  return enif_make_atom(env, "ok");
}

static int is_boolean(ErlNifEnv* env, ERL_NIF_TERM term) {

  if (enif_is_identical(term, enif_make_atom(env, "true"))) {
    return 1;
  } else if (enif_is_identical(term, enif_make_atom(env, "false"))) {
    return 0;
  } else {
    return -1;
  }
}

static unsigned copy_attribute_value(
  ErlNifEnv* env, ERL_NIF_TERM term,
  attribute_info_t* attribute_info,
  CK_VOID_PTR value, unsigned remaining_size) {

  ErlNifBinary binary = {0};
  int bool_value = 0;
  unsigned value_size = 0;
  CK_ULONG ulong_value = 0;
  CK_LONG long_value = 0;
  int res = 0;

  P11_debug("copy_attribute_value: enter, t=%T, n=%s vt=%d", 
    term, attribute_info->name, attribute_info->value_type);

  switch(attribute_info->value_type) {

    case P11_ATTR_TYPE_BOOL:
      P11_debug("copy_attribute_value: bool");
      value_size = sizeof(CK_BBOOL);
      if (remaining_size < value_size) {
        return -1;
      }
      bool_value = is_boolean(env, term);
      if (bool_value < 0) {
        return -2; /* term is not a boolean */
      } else {
        *((CK_BBOOL*) value) = bool_value ? CK_TRUE : CK_FALSE;
        return value_size;
      }

    case P11_ATTR_TYPE_ULONG:
      P11_debug("copy_attribute_value: ulong");
      value_size = sizeof(CK_ULONG);
      if (remaining_size < value_size) {
        return -1; /* value buffer too small */
      }
      if (!enif_get_ulong(env, term, &ulong_value)) {
        return -2; /* term value is not a valid unsigned long */
      }
      *((CK_ULONG_PTR) value) = ulong_value;
      return value_size;

    case P11_ATTR_TYPE_LONG:
      P11_debug("copy_attribute_value: long");
      value_size = sizeof(CK_LONG);
      if (remaining_size < value_size) {
        return -1;
      }
      if (!enif_get_long(env, term, &long_value)) {
        return -2;
      }
      *((CK_LONG*) value) = long_value;
      return value_size;

    case P11_ATTR_TYPE_STRING:
    case P11_ATTR_TYPE_BYTES:
      P11_debug("copy_attribute_value: string");
      if (!enif_inspect_binary(env, term, &binary)) {
        return -2;
      }
      if (binary.size > remaining_size) {
        return -1;
      }
      memcpy(value, binary.data, binary.size);
      return binary.size;
 
    case P11_ATTR_TYPE_CLASS:
      P11_debug("copy_attribute_value: class");
      if (remaining_size < sizeof(CK_OBJECT_CLASS)) {
        return -1; /* value buffer too small */
      }
      res = object_class_from_term(env, term, (CK_OBJECT_CLASS*) value);
      if (res < 0) {
        return res; /* error in object_class_from_term */
      }
      return sizeof(CK_OBJECT_CLASS);

    case P11_ATTR_TYPE_KEY:
      P11_debug("copy_attribute_value: key");
      if (remaining_size < sizeof(CK_KEY_TYPE)) {
        return -1;
      } 
      res = key_type_from_term(env, term, (CK_KEY_TYPE*) value);
      if (res < 0) {
        return -2;
      }
      return sizeof(CK_KEY_TYPE);

    default:
      /* not implemented */
      P11_debug("copy_attribute_value: unsupported attribute type %ul", 
        attribute_info->value_type);
      return -3;
  }
  
  /* A binary string may be mapped to a byte array or a string, 
     depending on the attribute. */
 if (enif_is_binary(env, term)) {
    if (enif_inspect_binary(env, term, &binary)) {
      value_size = binary.size;
      
    } else {
      return -1;
    }
  }

  return -2;
}

static attribute_info_t *find_attribute_info_by_id(CK_ULONG attribute_id) {

  for (size_t i = 0; i < ATTRIBUTE_INFO_COUNT; i++) {
    if (attribute_info[i].id == attribute_id) {
      return (attribute_info_t *)&attribute_info[i];
    }
  }
  return NULL;
}

static attribute_info_t *find_attribute_info_by_name(const char *name) {

  for (size_t i = 0; i < ATTRIBUTE_INFO_COUNT; i++) {
    if (strcmp(attribute_info[i].name, name) == 0) {
      return (attribute_info_t *)&attribute_info[i];
    }
  }
  return NULL;
}

static ERL_NIF_TERM attribute_to_term(ErlNifEnv* env, CK_ATTRIBUTE* attribute) {

  attribute_info_t* attr_info = NULL;
  CK_ULONG attr_id = 0;
  CK_BBOOL bool_value = CK_FALSE;
  ERL_NIF_TERM value_term, attr_name;
  ErlNifBinary binary;
  CK_DATE* date = NULL;
  char date_str[11] = {0}; /* YYYY-MM-DD plus null terminator */

  P11_debug("attribute_to_term: enter attribute=%p", attribute);

  attr_info = find_attribute_info_by_id(attribute->type);
  if (attr_info == NULL) {
    if (enif_get_ulong(env, attribute->type, &attr_id)) {
      return enif_make_tuple3(env, 
        enif_make_atom(env, "error"), 
        enif_make_atom(env, "unknown_attribute"),
        enif_make_ulong(env, attr_id));
    } else {
      return enif_make_tuple2(env, 
        enif_make_atom(env, "error"), 
        enif_make_atom(env, "unknown_attribute"));
    }
  }
  
  attr_name = enif_make_atom(env, attr_info->name);
  P11_debug("attribute_to_term: attr_name=%s vt=%d", attr_info->name, attr_info->value_type);
  
  if (attribute->ulValueLen == 0) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "ok"), 
      enif_make_tuple2(env, attr_name, enif_make_atom(env, "inaccessible")));
  }

  switch(attr_info->value_type) {

    case P11_ATTR_TYPE_BOOL:
      bool_value = *((CK_BBOOL*) attribute->pValue);
      value_term = bool_value ? enif_make_atom(env, "true") : enif_make_atom(env, "false");
      return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"), 
        enif_make_tuple2(env, attr_name, value_term));

    case P11_ATTR_TYPE_CLASS:
      value_term = object_class_to_term(env, *((CK_OBJECT_CLASS*) attribute->pValue));
      return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"), 
        enif_make_tuple2(env, attr_name, value_term));

    case P11_ATTR_TYPE_KEY:
      value_term = key_type_to_term(env, *((CK_KEY_TYPE*) attribute->pValue));
      return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"), 
        enif_make_tuple2(env, attr_name, value_term));

    case P11_ATTR_TYPE_ULONG:
      value_term = enif_make_ulong(env, *((CK_ULONG*) attribute->pValue));
      return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"), 
        enif_make_tuple2(env, attr_name, value_term));

    case P11_ATTR_TYPE_LONG:
      value_term = enif_make_long(env, *((CK_LONG*) attribute->pValue));
      return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"), 
        enif_make_tuple2(env, attr_name, value_term));

    case P11_ATTR_TYPE_STRING:
      value_term = p11str_to_term(env, (CK_UTF8CHAR_PTR) attribute->pValue, attribute->ulValueLen);
      return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"), 
        enif_make_tuple2(env, attr_name, value_term));

    case P11_ATTR_TYPE_BIGINT:
    case P11_ATTR_TYPE_BYTES:
      P11_debug("attribute_to_term: allocating binary for %lu bytes", attribute->ulValueLen);
      if (!enif_alloc_binary(attribute->ulValueLen, &binary)) {
        return enif_make_tuple2(env, 
          enif_make_atom(env, "error"), 
          enif_make_atom(env, "memory_allocation_failed"));
      }
      memcpy(binary.data, attribute->pValue, attribute->ulValueLen);
      binary.size = attribute->ulValueLen;
      return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"), 
        enif_make_tuple2(env, attr_name, enif_make_binary(env, &binary)));

    case P11_ATTR_TYPE_DATE:
      P11_debug("attribute_to_term: date attribute=%p length=%lu", 
        attribute->pValue, attribute->ulValueLen);
      date = (CK_DATE*) attribute->pValue;
      P11_debug("attribute_to_term: date=%p year=%s month=%s day=%s", 
        date, date->year, date->month, date->day);
      strncpy(date_str, date->year, 4);
      date_str[4] = '-';
      strncpy(date_str + 5, date->month, 2);
      date_str[7] = '-';
      strncpy(date_str + 8, date->day, 2);
      date_str[10] = '\0';
      P11_debug("attribute_to_term: date_str=%s", date_str);
      value_term = enif_make_string(env, date_str, ERL_NIF_UTF8);
      return enif_make_tuple2(env, enif_make_atom(env, "ok"), value_term);

    case P11_ATTR_TYPE_MECHANISM:
      value_term = ckm_to_atom(env, *((CK_MECHANISM_TYPE*) attribute->pValue));
      return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"), 
        enif_make_tuple2(env, attr_name, value_term));

    default:
      return enif_make_tuple3(env, 
        enif_make_atom(env, "error"), 
        enif_make_atom(env, "unsupported_attribute_type"),
        attr_name);
  }


  if (attr_info == NULL) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "unknown_attribute"));
  }

}

static ERL_NIF_TERM encrypt_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_MECHANISM mechanism = {0};
  CK_OBJECT_HANDLE key_handle = 0;
  ERL_NIF_TERM mech_conversion_result;

  P11_debug("encrypt_init: enter");
  REQUIRE_ARGS(env, argc, 4);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: mechanism */
  if (!enif_is_tuple(env, argv[2])) {
    return enif_make_badarg(env);
  }

  /* argv[3]: key handle */
  ULONG_ARG(env, argv[3], key_handle);

  mech_conversion_result = term_to_mechanism(env, argv[2], &mechanism);
  P11_debug("encrypt_init: mech_conversion_result=%T", mech_conversion_result);
  if (enif_compare(mech_conversion_result, enif_make_atom(env, "ok")) != 0) {
    return mech_conversion_result;
  }
  P11_debug("encrypt_init: converted mechanism %p", &mechanism);
  P11_debug_mechanism(&mechanism);

  P11_call(rv, p11_module, C_EncryptInit, session_handle, &mechanism, key_handle);
  if (rv != CKR_OK) {
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    return P11_error(env, "C_EncryptInit", rv);
  }

  if (mechanism.pParameter != NULL) {
    free(mechanism.pParameter);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM encrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[] ) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_in = {0}, data_out = {0}; 
  ERL_NIF_TERM data_out_term;
  CK_ULONG res_len1 = 0;
  CK_ULONG res_len2 = 0;

  P11_debug("encrypt: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: data */
  if (!enif_inspect_binary(env, argv[2], &data_in)) {
    return enif_make_badarg(env);
  }

  P11_debug("Calling C_Encrypt to determine output length, input length: %lu", data_in.size);

  /* Call the function with NULL as the output buffer, 
     because we want to get the length of the result. */
  P11_call(rv, p11_module, C_Encrypt, session_handle, 
    data_in.data, data_in.size, NULL, &res_len1);
  if (rv != CKR_OK) {
    return P11_error(env, "C_Encrypt", rv);
  }
  P11_debug("C_Encrypt expected result length: %lu", res_len1);

  if (!enif_alloc_binary(res_len1, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  P11_debug("Allocated memory for data_out: %lu bytes at %p", data_out.size, data_out.data);

  secure_zero(data_out.data, data_out.size);

  /* Now we do the encryption. */
  res_len2 = data_out.size;
  P11_call(rv, p11_module, C_Encrypt, session_handle, 
    data_in.data, data_in.size, data_out.data, &res_len2);
  P11_debug("C_Encrypt result length: %lu", res_len2);
  if (rv != CKR_OK) {
    enif_release_binary(&data_out);
    return P11_error(env, "C_Encrypt", rv);
  }

  data_out_term = enif_make_binary(env, &data_out);

  return enif_make_tuple2(env, 
    enif_make_atom(env, "ok"), 
    data_out_term);
}

static ERL_NIF_TERM encrypt_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_in = {0}, data_out = {0}; 
  ERL_NIF_TERM data_out_term;
  CK_ULONG expected_res_len = 0;
  CK_ULONG actual_res_len = 0;

  P11_debug("encrypt_update: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: data */
  if (!enif_inspect_binary(env, argv[2], &data_in)) {
    return enif_make_badarg(env);
  }
  
  P11_debug("Calling C_EncryptUpdate to determine output length, input length: %lu", data_in.size);
  /* Call the function with NULL as the output buffer, 
     because we want to get the length of the result. */
  P11_call(rv, p11_module, C_EncryptUpdate, session_handle, 
    data_in.data, data_in.size, NULL, &expected_res_len);
  if (rv != CKR_OK) {
    return P11_error(env, "C_EncryptUpdate", rv);
  }
  P11_debug("C_EncryptUpdate expected result length: %lu", expected_res_len);

  if (!enif_alloc_binary(expected_res_len, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  P11_debug("Allocated memory for data_out: %lu bytes at %p", data_out.size, data_out.data);

  secure_zero(data_out.data, data_out.size);

  /* Now we do the encryption. */
  actual_res_len = data_out.size;
  P11_call(rv, p11_module, C_EncryptUpdate, session_handle, 
    data_in.data, data_in.size, data_out.data, &actual_res_len);
  P11_debug("C_EncryptUpdate result length: %lu", actual_res_len);
  if (rv != CKR_OK) {
    enif_release_binary(&data_out);
    return P11_error(env, "C_EncryptUpdate", rv);
  }

  if (actual_res_len != expected_res_len) {
    enif_release_binary(&data_out);
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "unexpected_result_length"));
  }

  data_out_term = enif_make_binary(env, &data_out);

  return enif_make_tuple2(env, 
    enif_make_atom(env, "ok"), 
    data_out_term);
}

static ERL_NIF_TERM encrypt_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_out = {0};
  ERL_NIF_TERM data_out_term;
  CK_ULONG expected_res_len = 0;
  CK_ULONG actual_res_len = 0;

  P11_debug("encrypt_final: enter");
  REQUIRE_ARGS(env, argc, 2);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* Call the function with NULL as the output buffer, 
     because we want to get the length of the result. */
  P11_call(rv, p11_module, C_EncryptFinal, session_handle, NULL, &expected_res_len);
  P11_debug("C_EncryptFinal expected result length: %lu", expected_res_len);

  if (!enif_alloc_binary(expected_res_len, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  secure_zero(data_out.data, data_out.size);

  actual_res_len = data_out.size;
  P11_call(rv, p11_module, C_EncryptFinal, session_handle, data_out.data, &actual_res_len);
  if (rv != CKR_OK) {
    enif_release_binary(&data_out);
    return P11_error(env, "C_EncryptFinal", rv);
  }
  P11_debug("C_EncryptFinal actual result length: %lu", actual_res_len);

  if (actual_res_len < expected_res_len) {
    if (!enif_realloc_binary(&data_out, actual_res_len)) {
      enif_release_binary(&data_out);
      return enif_make_tuple2(env, 
        enif_make_atom(env, "error"), 
        enif_make_atom(env, "unexpected_result_length"));
    }
  }

  data_out_term = enif_make_binary(env, &data_out);

  return enif_make_tuple2(env, 
    enif_make_atom(env, "ok"), 
    data_out_term);
}

static ERL_NIF_TERM decrypt_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_MECHANISM mechanism = {0};
  CK_OBJECT_HANDLE key_handle = 0;
  ERL_NIF_TERM mech_conversion_result;

  P11_debug("decrypt_init: enter");
  REQUIRE_ARGS(env, argc, 4);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: mechanism */
  if (!enif_is_tuple(env, argv[2])) {
    return enif_make_badarg(env);
  }

  /* argv[3]: key handle */
  ULONG_ARG(env, argv[3], key_handle);

  mech_conversion_result = term_to_mechanism(env, argv[2], &mechanism);
  P11_debug("decrypt_init: mech_conversion_result=%T", mech_conversion_result);
  if (enif_compare(mech_conversion_result, enif_make_atom(env, "ok")) != 0) {
    return mech_conversion_result;
  }
  P11_debug("decrypt_init: converted mechanism %p", &mechanism);
  P11_debug_mechanism(&mechanism);

  P11_call(rv, p11_module, C_DecryptInit, session_handle, &mechanism, key_handle);
  if (rv != CKR_OK) {
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    return P11_error(env, "C_DecryptInit", rv);
  }

  if (mechanism.pParameter != NULL) {
    free(mechanism.pParameter);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM decrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_in = {0}, data_out = {0}; 
  ERL_NIF_TERM data_out_term;
  CK_ULONG res_len1 = 0;
  CK_ULONG res_len2 = 0;

  P11_debug("encrypt: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: data */
  if (!enif_inspect_binary(env, argv[2], &data_in)) {
    return enif_make_badarg(env);
  }

  P11_debug("Calling C_Decrypt to determine output length, input length: %lu", data_in.size);

  /* Call the function with NULL as the output buffer, 
     because we want to get the length of the result. */
  P11_call(rv, p11_module, C_Decrypt, session_handle, data_in.data, data_in.size, NULL, &res_len1);
  if (rv != CKR_OK) {
    return P11_error(env, "C_Decrypt", rv);
  }
  P11_debug("C_Decrypt expected result length: %lu", res_len1);

  if (!enif_alloc_binary(res_len1, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  P11_debug("Allocated memory for data_out: %lu bytes at %p", data_out.size, data_out.data);

  secure_zero(data_out.data, data_out.size);

  /* Now we do the decryption. */
  res_len2 = data_out.size;
  P11_call(rv, p11_module, C_Decrypt, session_handle, data_in.data, data_in.size, data_out.data, &res_len2);
  P11_debug("C_Decrypt result length: %lu", res_len2);
  if (rv != CKR_OK) {
    enif_release_binary(&data_out);
    return P11_error(env, "C_Decrypt", rv);
  }

  if (res_len2 < res_len1) {
    P11_debug("C_Decrypt result length is less than expected, res_len2: %lu, res_len1: %lu", res_len2, res_len1);
    if (!enif_realloc_binary(&data_out, res_len2)) {
      enif_release_binary(&data_out);
      return enif_make_tuple2(env, 
        enif_make_atom(env, "error"), 
        enif_make_atom(env, "memory_reallocation_failed"));
    }
  }

  data_out_term = enif_make_binary(env, &data_out);

  return enif_make_tuple2(env, 
    enif_make_atom(env, "ok"), 
    data_out_term);
}

static ERL_NIF_TERM decrypt_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_in = {0}, data_out = {0}; 
  ERL_NIF_TERM data_out_term;
  CK_ULONG expected_res_len = 0;
  CK_ULONG actual_res_len = 0;

  P11_debug("decrypt_update: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: data */
  if (!enif_inspect_binary(env, argv[2], &data_in)) {
    return enif_make_badarg(env);
  }

  P11_debug("Calling C_DecryptUpdate to determine output length, input length: %lu", data_in.size);
  /* Call the function with NULL as the output buffer, 
     because we want to get the length of the result. */
  P11_call(rv, p11_module, C_DecryptUpdate, session_handle, 
    data_in.data, data_in.size, NULL, &expected_res_len);
  P11_debug("C_DecryptUpdate expected result length: %lu", expected_res_len);
  if (rv != CKR_OK) {
    return P11_error(env, "C_DecryptUpdate", rv);
  }

  if (!enif_alloc_binary(expected_res_len, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  P11_debug("Allocated memory for data_out: %lu bytes at %p", data_out.size, data_out.data);

  secure_zero(data_out.data, data_out.size);

  /* Now we do the decryption. */
  actual_res_len = data_out.size;
  P11_call(rv, p11_module, C_DecryptUpdate, session_handle, 
    data_in.data, data_in.size, data_out.data, &actual_res_len);
  P11_debug("C_DecryptUpdate result length: %lu", actual_res_len);
  if (rv != CKR_OK) {
    return P11_error(env, "C_DecryptUpdate", rv);
  }

  if (actual_res_len < expected_res_len) {
    if (!enif_realloc_binary(&data_out, actual_res_len)) {
      enif_release_binary(&data_out);
      return enif_make_tuple2(env, 
        enif_make_atom(env, "error"), 
        enif_make_atom(env, "unexpected_result_length"));
    }
  }

  if (!enif_alloc_binary(actual_res_len, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  P11_debug("Allocated memory for data_out: %lu bytes at %p", data_out.size, data_out.data);

  data_out_term = enif_make_binary(env, &data_out);

  return enif_make_tuple2(env, 
    enif_make_atom(env, "ok"), 
    data_out_term);
}

static ERL_NIF_TERM decrypt_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_out = {0};
  ERL_NIF_TERM data_out_term;
  CK_ULONG expected_res_len = 0;
  CK_ULONG actual_res_len = 0;

  P11_debug("decrypt_final: enter");
  REQUIRE_ARGS(env, argc, 2);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* Call the function with NULL as the output buffer, 
     because we want to get the length of the result. */
  P11_call(rv, p11_module, C_DecryptFinal, session_handle, NULL, &expected_res_len);

  if (!enif_alloc_binary(expected_res_len, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  P11_debug("Allocated memory for data_out: %lu bytes at %p", data_out.size, data_out.data);

  secure_zero(data_out.data, data_out.size);
  actual_res_len = data_out.size;
  P11_call(rv, p11_module, C_DecryptFinal, session_handle, data_out.data, &actual_res_len);
  if (rv != CKR_OK) {
    enif_release_binary(&data_out);
    return P11_error(env, "C_DecryptFinal", rv);
  }

  if (actual_res_len < expected_res_len) {
    P11_debug("C_DecryptFinal result length is less than expected, actual_res_len: %lu, expected_res_len: %lu", actual_res_len, expected_res_len);
    if (!enif_realloc_binary(&data_out, actual_res_len)) {
      enif_release_binary(&data_out);
      return enif_make_tuple2(env, 
        enif_make_atom(env, "error"), 
        enif_make_atom(env, "unexpected_result_length"));
    }
  }

  data_out_term = enif_make_binary(env, &data_out);

  return enif_make_tuple2(env, 
    enif_make_atom(env, "ok"), 
    data_out_term);
}

static ERL_NIF_TERM generate_random(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_ULONG requested_length = 0;
  ErlNifBinary data_out = {0};
  ERL_NIF_TERM data_out_term;

  P11_debug("generate_random: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: request output length */
  ULONG_ARG(env, argv[2], requested_length);

  if (!enif_alloc_binary(requested_length, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  P11_debug("Allocated memory for data_out: %lu bytes at %p", data_out.size, data_out.data);
  secure_zero(data_out.data, data_out.size);

  P11_call(rv, p11_module, C_GenerateRandom, session_handle, data_out.data, data_out.size);
  if (rv != CKR_OK) {
    enif_release_binary(&data_out);
    return P11_error(env, "C_GenerateRandom", rv);
  }

  data_out_term = enif_make_binary(env, &data_out);

  return enif_make_tuple2(env, 
    enif_make_atom(env, "ok"), 
    data_out_term);
}

static ERL_NIF_TERM destroy_object(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_OBJECT_HANDLE object_handle = 0;

  P11_debug("destroy_object: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: object handle */
  ULONG_ARG(env, argv[2], object_handle);

  P11_call(rv, p11_module, C_DestroyObject, session_handle, object_handle);
  if (rv != CKR_OK) {
    return P11_error(env, "C_DestroyObject", rv);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM list_mechanisms(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SLOT_ID slot_id = 0;
  CK_ULONG mechanism_count = 0;
  CK_MECHANISM_TYPE_PTR mechanism_list = NULL;

  P11_debug("list_mechanisms: enter");
  REQUIRE_ARGS(env, argc, 2);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: slot id */
  ULONG_ARG(env, argv[1], slot_id);

  P11_call(rv, p11_module, C_GetMechanismList, slot_id, NULL_PTR, &mechanism_count);
  if (rv != CKR_OK) {
    return P11_error(env, "C_GetMechanismList", rv);
  }

  P11_debug("list_mechanisms: mechanism_count=%lu", mechanism_count);

  mechanism_list = (CK_MECHANISM_TYPE_PTR) calloc(mechanism_count, sizeof(CK_MECHANISM_TYPE));
  if (mechanism_list == NULL) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }

  P11_call(rv, p11_module, C_GetMechanismList, slot_id, mechanism_list, &mechanism_count);
  if (rv != CKR_OK) {
    free(mechanism_list);
    return P11_error(env, "C_GetMechanismList", rv);
  }

  ERL_NIF_TERM list = enif_make_list(env, 0);
  for (CK_ULONG i = 0; i < mechanism_count; i++) {
    list = enif_make_list_cell(env, ckm_to_atom(env, mechanism_list[i]), list);
  }

  free(mechanism_list);
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), list);
}

static ERL_NIF_TERM mechanism_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SLOT_ID slot_id = 0;
  CK_MECHANISM_TYPE mechanism_type = 0;
  CK_MECHANISM_INFO mechanism_info = {0};

  P11_debug("mechanism_info: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: slot id */
  ULONG_ARG(env, argv[1], slot_id);

  /* argv[2]: mechanism type */
  if (mechanism_type_from_term(env, argv[2], &mechanism_type) < 0) {
    return enif_make_badarg(env);
  } 

  P11_debug("mechanism_info: slot_id=%lu, mechanism_type=0x%lx", slot_id, mechanism_type);
  P11_call(rv, p11_module, C_GetMechanismInfo, slot_id, mechanism_type, &mechanism_info);
  if (rv != CKR_OK) {
    return P11_error(env, "C_GetMechanismInfo", rv);
  }

  P11_debug("mechanism_info: min_key_size=%lu, max_key_size=%lu, flags=%lu", 
    mechanism_info.ulMinKeySize, mechanism_info.ulMaxKeySize, mechanism_info.flags);

  return enif_make_tuple2(env, 
          enif_make_atom(env, "ok"), 
          enif_make_tuple3(env, 
            enif_make_ulong(env, mechanism_info.ulMinKeySize), 
            enif_make_ulong(env, mechanism_info.ulMaxKeySize), 
            enif_make_ulong(env, mechanism_info.flags)));
}

/*
         _____ _             _            
        / ___/(_)___ _____  (_)___  ____ _
        \__ \/ / __ `/ __ \/ / __ \/ __ `/
       ___/ / / /_/ / / / / / / / / /_/ / 
      /____/_/\__, /_/ /_/_/_/ /_/\__, /  
             /____/              /____/   
*/

static ERL_NIF_TERM sign_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_OBJECT_HANDLE key_handle = 0;
  CK_MECHANISM mechanism = {0};
  ERL_NIF_TERM mech_conversion_result;

  P11_debug("sign_init: enter");
  REQUIRE_ARGS(env, argc, 4);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[3]: key handle */
  ULONG_ARG(env, argv[3], key_handle);

  /* argv[2]: mechanism type */
  mech_conversion_result = term_to_mechanism(env, argv[2], &mechanism);
  P11_debug("sign_init: mechanism conversion result: %T", mech_conversion_result);
  if (enif_compare(mech_conversion_result, enif_make_atom(env, "ok")) != 0) {
    return mech_conversion_result;
  }
  P11_debug("sign_init: converted mechanism %p", &mechanism);
  P11_debug_mechanism(&mechanism);
  
  P11_call(rv, p11_module, C_SignInit, session_handle, &mechanism, key_handle);
  if (rv != CKR_OK) {
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    return P11_error(env, "C_SignInit", rv);
  }

  if (mechanism.pParameter != NULL) {
    free(mechanism.pParameter);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_in = {0}, data_out = {0};
  ERL_NIF_TERM data_out_term;
  CK_ULONG res_len1 = 0, res_len2 = 0;

  P11_debug("sign: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: data */
  if (!enif_inspect_binary(env, argv[2], &data_in)) {
    return enif_make_badarg(env);
  }

  /* Call the function with NULL as the output buffer, to get the size of the output */
  P11_debug("sign: calling C_Sign with NULL output buffer to get the size of the output");
  P11_call(rv, p11_module, C_Sign, session_handle, data_in.data, data_in.size, NULL_PTR, &res_len1);
  if (rv != CKR_OK) {
    return P11_error(env, "C_Sign", rv);
  }
  P11_debug("sign: C_Sign expected output size: %lu", res_len1);

  if (!enif_alloc_binary(res_len1, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }

  secure_zero(data_out.data, data_out.size);

  P11_debug("sign: calling C_Sign with the allocated output buffer");
  res_len2 = data_out.size;
  P11_call(rv, p11_module, C_Sign, session_handle, data_in.data, data_in.size, data_out.data, &res_len2);
  P11_debug("sign: C_Sign result length: %lu  ", res_len2);

  if (rv != CKR_OK) {
    enif_release_binary(&data_out);
    return P11_error(env, "C_Sign", rv);
  }
  
  if (res_len2 != data_out.size) {
    enif_release_binary(&data_out);
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "unexpected_output_length"));
  }

  data_out_term = enif_make_binary(env, &data_out);
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), data_out_term);
}

static ERL_NIF_TERM sign_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_in = {0};

  P11_debug("sign_update: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: data */
  if (!enif_inspect_binary(env, argv[2], &data_in)) {
    return enif_make_badarg(env);
  }

  P11_call(rv, p11_module, C_SignUpdate, session_handle, data_in.data, data_in.size);
  if (rv != CKR_OK) {
    return P11_error(env, "C_SignUpdate", rv);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM sign_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_out = {0};
  ERL_NIF_TERM data_out_term;
  CK_ULONG expected_res_len = 0;
  CK_ULONG actual_res_len = 0;

  P11_debug("sign_final: enter");
  REQUIRE_ARGS(env, argc, 2);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  P11_debug("sign_final: Calling C_SignFinal with NULL output buffer to get the size of the output");
  P11_call(rv, p11_module, C_SignFinal, session_handle, NULL_PTR, &expected_res_len);
  if (rv != CKR_OK) {
    return P11_error(env, "C_SignFinal", rv);
  }
  P11_debug("sign_final: C_SignFinal expected output size: %lu", expected_res_len);

  if (!enif_alloc_binary(expected_res_len, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  secure_zero(data_out.data, data_out.size);

  actual_res_len = data_out.size;
  P11_call(rv, p11_module, C_SignFinal, session_handle, data_out.data, &actual_res_len);
  P11_debug("sign_final: C_SignFinal result length: %lu", actual_res_len);
  if (rv != CKR_OK) {
    enif_release_binary(&data_out);
    return P11_error(env, "C_SignFinal", rv);
  }

  if (actual_res_len != expected_res_len) {
    enif_release_binary(&data_out);
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "unexpected_output_length"));
  }

  data_out_term = enif_make_binary(env, &data_out);

  return enif_make_tuple2(env, enif_make_atom(env, "ok"), data_out_term);
}  

/*
         _    __          _ ____     
        | |  / /__  _____(_) __/_  __
        | | / / _ \/ ___/ / /_/ / / /
        | |/ /  __/ /  / / __/ /_/ / 
        |___/\___/_/  /_/_/  \__, /  
                            /____/   
*/

static ERL_NIF_TERM verify_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_OBJECT_HANDLE key_handle = 0;
  CK_MECHANISM mechanism = {0};
  ERL_NIF_TERM mech_conversion_result;

  P11_debug("verify_init: enter");
  REQUIRE_ARGS(env, argc, 4);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[3]: key handle */
  ULONG_ARG(env, argv[3], key_handle);

  /* argv[2]: mechanism type */
  mech_conversion_result = term_to_mechanism(env, argv[2], &mechanism);
  P11_debug("sign_init: mechanism conversion result: %T", mech_conversion_result);
  if (enif_compare(mech_conversion_result, enif_make_atom(env, "ok")) != 0) {
    return mech_conversion_result;
  }
  P11_debug("sign_init: converted mechanism %p", &mechanism);
  P11_debug_mechanism(&mechanism);

  P11_call(rv, p11_module, C_VerifyInit, session_handle, &mechanism, key_handle);
  if (rv != CKR_OK) {
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    return P11_error(env, "C_VerifyInit", rv);
  }

  if (mechanism.pParameter != NULL) {
    free(mechanism.pParameter);
  }

  return enif_make_atom(env, "ok");
}
  
static ERL_NIF_TERM verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data = {0}, signature = {0};
  
  P11_debug("verify: enter");
  REQUIRE_ARGS(env, argc, 4);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: data */
  if (!enif_inspect_binary(env, argv[2], &data)) {
    return enif_make_badarg(env);
  }

  /* argv[3]: signature */
  if (!enif_inspect_binary(env, argv[3], &signature)) {
    return enif_make_badarg(env);
  }

  P11_debug("verify: calling C_Verify data=%p len=%lu sig=%p len=%lu", 
    data.data, data.size, signature.data, signature.size);
  P11_call(rv, p11_module, C_Verify, session_handle, data.data, data.size, signature.data, signature.size);
  if (rv != CKR_OK) {
    return P11_error(env, "C_Verify", rv);
  }

  return enif_make_atom(env, "ok");
}


/*
         ____  _                 __ 
        / __ \(_)___ ____  _____/ /_
       / / / / / __ `/ _ \/ ___/ __/
      / /_/ / / /_/ /  __(__  ) /_  
     /_____/_/\__, /\___/____/\__/  
             /____/                 
*/

static ERL_NIF_TERM digest_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_MECHANISM mechanism = {0};
  ERL_NIF_TERM conversion_result;

  P11_debug("digest_init: enter");
  REQUIRE_ARGS(env, argc, 3);
  
  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: mechanism type */
  conversion_result = term_to_mechanism(env, argv[2], &mechanism);
  P11_debug("digest_init: mechanism conversion result: %T", conversion_result);
  if (enif_compare(conversion_result, enif_make_atom(env, "ok")) != 0) {
    return conversion_result;
  }
  P11_debug("digest_init: converted mechanism %p", &mechanism);
  P11_debug_mechanism(&mechanism);

  P11_call(rv, p11_module, C_DigestInit, session_handle, &mechanism);
  if (rv != CKR_OK) {
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    return P11_error(env, "C_DigestInit", rv);
  }

  if (mechanism.pParameter != NULL) {
    free(mechanism.pParameter);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM digest(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_in = {0}, data_out = {0};
  ERL_NIF_TERM data_out_term;
  CK_ULONG expected_res_len = 0;
  CK_ULONG actual_res_len = 0;

  P11_debug("digest: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: data */
  if (!enif_inspect_binary(env, argv[2], &data_in)) {
    return enif_make_badarg(env);
  }

  /* Call the function with NULL as the output buffer, to get the size of the output */
  P11_debug("digest: calling C_Digest with NULL output buffer to get the size of the output");
  P11_call(rv, p11_module, C_Digest, session_handle, data_in.data, data_in.size, NULL_PTR, &expected_res_len);
  if (rv != CKR_OK) {
    return P11_error(env, "C_Digest", rv);
  }
  P11_debug("digest: C_Digest expected output size: %lu", expected_res_len);
  
  if (!enif_alloc_binary(expected_res_len, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  
  secure_zero(data_out.data, data_out.size);
  
  P11_debug("digest: calling C_Digest with the allocated output buffer");
  actual_res_len = data_out.size;
  P11_call(rv, p11_module, C_Digest, session_handle, data_in.data, data_in.size, data_out.data, &actual_res_len);
  P11_debug("digest: C_Digest result length: %lu", actual_res_len);

  if (rv != CKR_OK) {
    enif_release_binary(&data_out);
    return P11_error(env, "C_Digest", rv);
  }

  if (actual_res_len != expected_res_len) {
    enif_release_binary(&data_out);
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "unexpected_output_length"));
  }

  data_out_term = enif_make_binary(env, &data_out);
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), data_out_term);
}


static ERL_NIF_TERM digest_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_in = {0};

  P11_debug("digest_update: enter");
  REQUIRE_ARGS(env, argc, 3);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: data */
  if (!enif_inspect_binary(env, argv[2], &data_in)) {
    return enif_make_badarg(env);
  }

  P11_call(rv, p11_module, C_DigestUpdate, session_handle, data_in.data, data_in.size);
  if (rv != CKR_OK) {
    return P11_error(env, "C_DigestUpdate", rv);
  }

  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM digest_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  ErlNifBinary data_out = {0};
  ERL_NIF_TERM data_out_term;
  CK_ULONG expected_res_len = 0;
  CK_ULONG actual_res_len = 0;

  P11_debug("digest_final: enter");
  REQUIRE_ARGS(env, argc, 2);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  } 

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* Call the function with NULL as the output buffer, to get the size of the output */
  P11_debug("digest_final: calling C_DigestFinal with NULL output buffer to get the size of the output");
  P11_call(rv, p11_module, C_DigestFinal, session_handle, NULL_PTR, &expected_res_len);
  if (rv != CKR_OK) {
    return P11_error(env, "C_DigestFinal", rv);
  }
  P11_debug("digest_final: C_DigestFinal expected output size: %lu", expected_res_len);

  if (!enif_alloc_binary(expected_res_len, &data_out)) {
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "memory_allocation_failed"));
  }
  secure_zero(data_out.data, data_out.size);

  P11_debug("digest_final: calling C_DigestFinal with the allocated output buffer");
  actual_res_len = data_out.size;
  P11_call(rv, p11_module, C_DigestFinal, session_handle, data_out.data, &actual_res_len);
  P11_debug("digest_final: C_DigestFinal result length: %lu", actual_res_len);
  if (rv != CKR_OK) {
    enif_release_binary(&data_out);
    return P11_error(env, "C_DigestFinal", rv);
  }

  if (actual_res_len != expected_res_len) {
    enif_release_binary(&data_out);
    return enif_make_tuple2(env, 
      enif_make_atom(env, "error"), 
      enif_make_atom(env, "unexpected_output_length"));
  }

  data_out_term = enif_make_binary(env, &data_out);

  return enif_make_tuple2(env, enif_make_atom(env, "ok"), data_out_term);
}

/*
         ______              __ __           ____        _     
        / ____/__  ____     / //_/__  __  __/ __ \____ _(_)____
       / / __/ _ \/ __ \   / ,< / _ \/ / / / /_/ / __ `/ / ___/
      / /_/ /  __/ / / /  / /| /  __/ /_/ / ____/ /_/ / / /    
      \____/\___/_/ /_/  /_/ |_\___/\__, /_/    \__,_/_/_/     
                                   /____/                      
*/

static ERL_NIF_TERM generate_key_pair(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

  CK_RV rv = CKR_GENERAL_ERROR;
  p11_module_t* p11_module = NULL;
  CK_SESSION_HANDLE session_handle = 0;
  CK_MECHANISM mechanism = {0};
  ERL_NIF_TERM mech_conv_res, pub_key_conv_res, priv_key_conv_res;
  CK_ATTRIBUTE_PTR pub_key_attributes = NULL;
  CK_ULONG pub_key_attributes_len = 0;
  CK_ATTRIBUTE_PTR priv_key_attributes = NULL;
  CK_ULONG priv_key_attributes_len = 0;
  CK_OBJECT_HANDLE pub_key_handle = 0;
  CK_OBJECT_HANDLE priv_key_handle = 0;
  ERL_NIF_TERM handle_tuple;

  P11_debug("generate_key_pair: enter");
  REQUIRE_ARGS(env, argc, 5);

  /* argv[0]: p11_module */
  if (!enif_get_resource(env, argv[0], p11_module_resource_type, (void**)&p11_module)) {
    return enif_make_badarg(env);
  }

  /* argv[1]: session handle */
  ULONG_ARG(env, argv[1], session_handle);

  /* argv[2]: mechanism type */
  mech_conv_res = term_to_mechanism(env, argv[2], &mechanism);
  if (enif_compare(mech_conv_res, enif_make_atom(env, "ok")) != 0) {
    return mech_conv_res;
  }
  P11_debug("generate_key_pair: converted mechanism %p", &mechanism);
  P11_debug_mechanism(&mechanism);
  
  /* argv[3]: public key template */
  if (!enif_is_list(env, argv[3])) {
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    return enif_make_badarg(env);
  }

  /* argv[4]: private key template */
  if (!enif_is_list(env, argv[4])) {
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    return enif_make_badarg(env);
  }

  /* convert public key template */
  pub_key_conv_res = term_to_attributes(env, argv[3], &pub_key_attributes, &pub_key_attributes_len);
  if (enif_compare(pub_key_conv_res, enif_make_atom(env, "ok")) != 0) {
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    return pub_key_conv_res;
  }

  /* convert private key template */
  priv_key_conv_res = term_to_attributes(env, argv[4], &priv_key_attributes, &priv_key_attributes_len);
  if (enif_compare(priv_key_conv_res, enif_make_atom(env, "ok")) != 0) {
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    if (pub_key_attributes != NULL) {
      free(pub_key_attributes[0].pValue);
      free(pub_key_attributes);
    }
    return priv_key_conv_res;
  }

  /* Now, actually generate the key pair */
  P11_call(rv, p11_module, C_GenerateKeyPair, session_handle, &mechanism,
     pub_key_attributes, pub_key_attributes_len, 
     priv_key_attributes, priv_key_attributes_len,
     &pub_key_handle, &priv_key_handle);
  if (rv != CKR_OK) {
    if (pub_key_attributes != NULL) {
      free(pub_key_attributes[0].pValue);
      free(pub_key_attributes);
    }
    if (priv_key_attributes != NULL) {
      free(priv_key_attributes[0].pValue);  
      free(priv_key_attributes);
    }
    if (mechanism.pParameter != NULL) {
      free(mechanism.pParameter);
    }
    return P11_error(env, "C_GenerateKeyPair", rv);
  }

  handle_tuple = 
    enif_make_tuple2(env, 
      enif_make_ulong(env, pub_key_handle),
      enif_make_ulong(env, priv_key_handle));

  if (mechanism.pParameter != NULL) {
    free(mechanism.pParameter);
  }
  if (pub_key_attributes != NULL) {
    free(pub_key_attributes[0].pValue);
    free(pub_key_attributes);
  }
  if (priv_key_attributes != NULL) {
    free(priv_key_attributes[0].pValue);
    free(priv_key_attributes);
  }
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), handle_tuple);
}




/*
    __  __     __                   ______                 __  _                 
   / / / /__  / /___  ___  _____   / ____/_  ______  _____/ /_(_)___  ____  _____
  / /_/ / _ \/ / __ \/ _ \/ ___/  / /_  / / / / __ \/ ___/ __/ / __ \/ __ \/ ___/
 / __  /  __/ / /_/ /  __/ /     / __/ / /_/ / / / / /__/ /_/ / /_/ / / / (__  ) 
/_/ /_/\___/_/ .___/\___/_/     /_/    \__,_/_/ /_/\___/\__/_/\____/_/ /_/____/  
            /_/                                                                  
*/

/* Forward declaration for the new function */
static const char* ckr_to_string(CK_RV rv);

/* Return an Erlang atom for a CK_RV error code by first converting to string */
static ERL_NIF_TERM ckr_to_atom(ErlNifEnv* env, CK_RV rv) {
    const char* rv_str = ckr_to_string(rv);
    if (rv_str != NULL) {
        return enif_make_atom(env, rv_str);
    }
    /* Handle vendor defined codes */
    return enif_make_tuple2(env, 
        enif_make_atom(env, "ckr_vendor_defined"),
        enif_make_uint(env, rv));
}

/* Convert CK_RV to its string representation without the CKR_ prefix */
static const char* ckr_to_string(CK_RV rv) {
    switch(rv) {
        case CKR_OK:                             return "ckr_ok";
        case CKR_CANCEL:                         return "ckr_cancel";
        case CKR_HOST_MEMORY:                    return "ckr_host_memory";
        case CKR_SLOT_ID_INVALID:                return "ckr_slot_id_invalid";
        case CKR_GENERAL_ERROR:                  return "ckr_general_error";
        case CKR_FUNCTION_FAILED:                return "ckr_function_failed";
        case CKR_ARGUMENTS_BAD:                  return "ckr_arguments_bad";
        case CKR_NO_EVENT:                       return "ckr_no_event";
        case CKR_NEED_TO_CREATE_THREADS:         return "ckr_need_to_create_threads";
        case CKR_CANT_LOCK:                      return "ckr_cant_lock";
        case CKR_ATTRIBUTE_READ_ONLY:            return "ckr_attribute_read_only";
        case CKR_ATTRIBUTE_SENSITIVE:            return "ckr_attribute_sensitive";
        case CKR_ATTRIBUTE_TYPE_INVALID:         return "ckr_attribute_type_invalid";
        case CKR_ATTRIBUTE_VALUE_INVALID:        return "ckr_attribute_value_invalid";
        case CKR_ACTION_PROHIBITED:              return "ckr_action_prohibited";
        case CKR_DATA_INVALID:                   return "ckr_data_invalid";
        case CKR_DATA_LEN_RANGE:                 return "ckr_data_len_range";
        case CKR_DEVICE_ERROR:                   return "ckr_device_error";
        case CKR_DEVICE_MEMORY:                  return "ckr_device_memory";
        case CKR_DEVICE_REMOVED:                 return "ckr_device_removed";
        case CKR_ENCRYPTED_DATA_INVALID:         return "ckr_encrypted_data_invalid";
        case CKR_ENCRYPTED_DATA_LEN_RANGE:       return "ckr_encrypted_data_len_range";
        case CKR_AEAD_DECRYPT_FAILED:            return "ckr_aead_decrypt_failed";
        case CKR_FUNCTION_CANCELED:              return "ckr_function_canceled";
        case CKR_FUNCTION_NOT_PARALLEL:          return "ckr_function_not_parallel";
        case CKR_FUNCTION_NOT_SUPPORTED:         return "ckr_function_not_supported";
        case CKR_KEY_HANDLE_INVALID:             return "ckr_key_handle_invalid";
        case CKR_KEY_SIZE_RANGE:                 return "ckr_key_size_range";
        case CKR_KEY_TYPE_INCONSISTENT:          return "ckr_key_type_inconsistent";
        case CKR_KEY_NOT_NEEDED:                 return "ckr_key_not_needed";
        case CKR_KEY_CHANGED:                    return "ckr_key_changed";
        case CKR_KEY_NEEDED:                     return "ckr_key_needed";
        case CKR_KEY_INDIGESTIBLE:               return "ckr_key_indigestible";
        case CKR_KEY_FUNCTION_NOT_PERMITTED:     return "ckr_key_function_not_permitted";
        case CKR_KEY_NOT_WRAPPABLE:              return "ckr_key_not_wrappable";
        case CKR_KEY_UNEXTRACTABLE:              return "ckr_key_unextractable";
        case CKR_MECHANISM_INVALID:              return "ckr_mechanism_invalid";
        case CKR_MECHANISM_PARAM_INVALID:        return "ckr_mechanism_param_invalid";
        case CKR_OBJECT_HANDLE_INVALID:          return "ckr_object_handle_invalid";
        case CKR_OPERATION_ACTIVE:               return "ckr_operation_active";
        case CKR_OPERATION_NOT_INITIALIZED:      return "ckr_operation_not_initialized";
        case CKR_PIN_INCORRECT:                  return "ckr_pin_incorrect";
        case CKR_PIN_INVALID:                    return "ckr_pin_invalid";
        case CKR_PIN_LEN_RANGE:                  return "ckr_pin_len_range";
        case CKR_PIN_EXPIRED:                    return "ckr_pin_expired";
        case CKR_PIN_LOCKED:                     return "ckr_pin_locked";
        case CKR_SESSION_CLOSED:                 return "ckr_session_closed";
        case CKR_SESSION_COUNT:                  return "ckr_session_count";
        case CKR_SESSION_HANDLE_INVALID:         return "ckr_session_handle_invalid";
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "ckr_session_parallel_not_supported";
        case CKR_SESSION_READ_ONLY:              return "ckr_session_read_only";
        case CKR_SESSION_EXISTS:                 return "ckr_session_exists";
        case CKR_SESSION_READ_ONLY_EXISTS:       return "ckr_session_read_only_exists";
        case CKR_SESSION_READ_WRITE_SO_EXISTS:   return "ckr_session_read_write_so_exists";
        case CKR_SIGNATURE_INVALID:              return "ckr_signature_invalid";
        case CKR_SIGNATURE_LEN_RANGE:            return "ckr_signature_len_range";
        case CKR_TEMPLATE_INCOMPLETE:            return "ckr_template_incomplete";
        case CKR_TEMPLATE_INCONSISTENT:          return "ckr_template_inconsistent";
        case CKR_TOKEN_NOT_PRESENT:              return "ckr_token_not_present";
        case CKR_TOKEN_NOT_RECOGNIZED:           return "ckr_token_not_recognized";
        case CKR_TOKEN_WRITE_PROTECTED:          return "ckr_token_write_protected";
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID:  return "ckr_unwrapping_key_handle_invalid";
        case CKR_UNWRAPPING_KEY_SIZE_RANGE:      return "ckr_unwrapping_key_size_range";
        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "ckr_unwrapping_key_type_inconsistent";
        case CKR_USER_ALREADY_LOGGED_IN:         return "ckr_user_already_logged_in";
        case CKR_USER_NOT_LOGGED_IN:             return "ckr_user_not_logged_in";
        case CKR_USER_PIN_NOT_INITIALIZED:       return "ckr_user_pin_not_initialized";
        case CKR_USER_TYPE_INVALID:              return "ckr_user_type_invalid";
        case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "ckr_user_another_already_logged_in";
        case CKR_USER_TOO_MANY_TYPES:            return "ckr_user_too_many_types";
        case CKR_WRAPPED_KEY_INVALID:            return "ckr_wrapped_key_invalid";
        case CKR_WRAPPED_KEY_LEN_RANGE:          return "ckr_wrapped_key_len_range";
        case CKR_WRAPPING_KEY_HANDLE_INVALID:    return "ckr_wrapping_key_handle_invalid";
        case CKR_WRAPPING_KEY_SIZE_RANGE:        return "ckr_wrapping_key_size_range";
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "ckr_wrapping_key_type_inconsistent";
        case CKR_RANDOM_SEED_NOT_SUPPORTED:      return "ckr_random_seed_not_supported";
        case CKR_RANDOM_NO_RNG:                  return "ckr_random_no_rng";
        case CKR_DOMAIN_PARAMS_INVALID:          return "ckr_domain_params_invalid";
        case CKR_CURVE_NOT_SUPPORTED:            return "ckr_curve_not_supported";
        case CKR_BUFFER_TOO_SMALL:               return "ckr_buffer_too_small";
        case CKR_SAVED_STATE_INVALID:            return "ckr_saved_state_invalid";
        case CKR_INFORMATION_SENSITIVE:          return "ckr_information_sensitive";
        case CKR_STATE_UNSAVEABLE:               return "ckr_state_unsaveable";
        case CKR_CRYPTOKI_NOT_INITIALIZED:       return "ckr_cryptoki_not_initialized";
        case CKR_CRYPTOKI_ALREADY_INITIALIZED:   return "ckr_cryptoki_already_initialized";
        case CKR_MUTEX_BAD:                      return "ckr_mutex_bad";
        case CKR_MUTEX_NOT_LOCKED:               return "ckr_mutex_not_locked";
        case CKR_NEW_PIN_MODE:                   return "ckr_new_pin_mode";
        case CKR_NEXT_OTP:                       return "ckr_next_otp";
        case CKR_EXCEEDED_MAX_ITERATIONS:        return "ckr_exceeded_max_iterations";
        case CKR_FIPS_SELF_TEST_FAILED:          return "ckr_fips_self_test_failed";
        case CKR_LIBRARY_LOAD_FAILED:            return "ckr_library_load_failed";
        case CKR_PIN_TOO_WEAK:                   return "ckr_pin_too_weak";
        case CKR_PUBLIC_KEY_INVALID:             return "ckr_public_key_invalid";
        case CKR_FUNCTION_REJECTED:              return "ckr_function_rejected";
        case CKR_TOKEN_RESOURCE_EXCEEDED:        return "ckr_token_resource_exceeded";
        case CKR_OPERATION_CANCEL_FAILED:        return "ckr_operation_cancel_failed";
        case CKR_KEY_EXHAUSTED:                  return "ckr_key_exhausted";
        default:                                 return NULL;
    }
}

static int mechanism_type_from_term(
    ErlNifEnv* env, ERL_NIF_TERM term, CK_MECHANISM_TYPE* out_mechanism_type) {
    
    CK_ULONG long_value = 0;
    char atom[MAX_MECHANISM_NAME_LENGTH];

    P11_debug("mechanism_type_from_term: term=%T", term);
    if (enif_is_number(env, term)) {
      if (!enif_get_ulong(env, term, &long_value)) {
        return -1;
      }
      *out_mechanism_type = (CK_MECHANISM_TYPE)long_value;  
      return 1;
    }

    if (enif_get_atom(env, term, atom, sizeof(atom), ERL_NIF_UTF8) <= 0) {
      return -1;
    }

    for (const mechanism_map_t *m = mechanism_map; m->name != NULL; m++) {
      if (strcmp(atom, m->name) == 0) {
        P11_debug("mechanism_type_from_term: mapped %s to 0x%lx", atom, m->value);
        *out_mechanism_type = m->value;
        return 1;
      }
    }

    return -1;
}

/* Convert Erlang atom to CK_OBJECT_CLASS and return it in out_object_class. 
   If we can't get the string value, return -1.
   If we don't know the object class, return -2.
   If we successfully convert the atom to the object class, return 1.
 */
static int object_class_from_term(ErlNifEnv* env, ERL_NIF_TERM term, CK_OBJECT_CLASS* out_object_class) {

  char atom[MAX_OBJECT_CLASS_NAME_LENGTH];

  if (enif_get_atom(env, term, atom, sizeof(atom), ERL_NIF_UTF8) <= 0) {
    return -1; /* term value is not an atom */
  }

  for (const object_class_map_t *m = object_class_map; m->name != NULL; m++) {
    if (strcmp(atom, m->name) == 0) {
      *out_object_class = m->value;
      return 1;
    }
  }

  return -2; /* object class not found */
}

/* Convert CK_OBJECT_CLASS to its Erlang atom representation. If we don't known the 
   value, return the value as a long. */
static ERL_NIF_TERM object_class_to_term(ErlNifEnv* env, CK_OBJECT_CLASS object_class) {

  for (const object_class_map_t *m = object_class_map; m->name != NULL; m++) {
    if (object_class == m->value) {
      return enif_make_atom(env, m->name);
    }
  }

  return enif_make_ulong(env, (CK_ULONG) object_class);
}

static int key_type_from_term(ErlNifEnv* env, ERL_NIF_TERM term, CK_KEY_TYPE* out_key_type) {

  char atom[MAX_KEY_TYPE_NAME_LENGTH];

  if (enif_get_atom(env, term, atom, sizeof(atom), ERL_NIF_UTF8) <= 0) {
    return -1;
  }

  for (const key_type_map_t *m = key_type_map; m->name != NULL; m++) {
    if (strcmp(atom, m->name) == 0) {
      *out_key_type = m->value;
      return 1;
    }
  }

  return -2;
}

static ERL_NIF_TERM key_type_to_term(ErlNifEnv* env, CK_KEY_TYPE key_type) {

  for (const key_type_map_t *m = key_type_map; m->name != NULL; m++) {
    if (key_type == m->value) {
      return enif_make_atom(env, m->name);
    }
  }

  return enif_make_ulong(env, (CK_ULONG) key_type);
}

/* Fill a memory area with zeros. */
static void secure_zero(void* ptr, size_t len) {
  P11_debug("secure_zero: ptr=%p len=%lu", ptr, len);
  volatile unsigned char *p = ptr;
  while (len--) {
    *p++ = 0;
  }
}

void resource_cleanup(ErlNifEnv* env, void* obj) {

  p11_module_t* p11_module = (p11_module_t*)obj;
  
  P11_debug("resource_cleanup: enter obj=%p", obj);
#if 0  
  if (p11_module) {
    /* Call C_Finalize if function list exists */
    if (p11_module->fun_list) {
      P11_call(rv, p11_module, C_Finalize, NULL);
      P11_debug("resource_cleanup: finalized PKCS#11 module, rv=%lu", rv);
      p11_module->fun_list = NULL;  /* Clear the pointer after using it */
    }

    /* In BEAM's environment, it's safer to skip dlclose() and let the OS 
       handle library cleanup when the process exits. Calling dlclose() can
       lead to memory corruption if the library is still being referenced. */
    P11_debug("resource_cleanup: NOT closing dynamic library to avoid memory corruption");
    p11_module->p11_module = NULL;
    P11_debug("resource_cleanup: cleaned up p11_module=%p", p11_module);
  }
#endif
}
