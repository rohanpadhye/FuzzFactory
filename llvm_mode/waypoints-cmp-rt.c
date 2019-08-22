#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "waypoints.h"

// Debug print statements
#ifdef WAYPOINTS_DEBUG_ON
#define WAYPOINTS_DEBUG(s, ...) printf("pc(0x%08x): ", __wrapcmp_program_loc); printf(s, __VA_ARGS__)
#else
#define WAYPOINTS_DEBUG(s, ...) 
#endif

// Allocate the the DSF map
FUZZFACTORY_DSF_NEW(__wrapcmp_dsf_map, MAP_SIZE, FUZZFACTORY_REDUCER_MAX, 0);

// Global variable used to store program location hash
u32 __wrapcmp_program_loc = 0;

#define BYTE0(x) ((u8) (((x) & 0xff)))
#define BYTE1(x) ((u8) (((x) & 0xff00) >> 8))
#define BYTE2(x) ((u8) (((x) & 0xff0000) >> 16))
#define BYTE3(x) ((u8) (((x) & 0xff000000) >> 24))
#define BYTE4(x) ((u8) (((x) & 0xff00000000LL) >> 32))
#define BYTE5(x) ((u8) (((x) & 0xff0000000000LL) >> 40))
#define BYTE6(x) ((u8) (((x) & 0xff000000000000LL) >> 48))
#define BYTE7(x) ((u8) (((x) & 0xff00000000000000LL) >> 54))

/* Maximize a value `v` at a key given by the current program location hash and current state */
#define WP_KEY()  __wrapcmp_program_loc
#define WP(v) FUZZFACTORY_DSF_MAX(__wrapcmp_dsf_map, WP_KEY(), v)

/* Increment the location hash; useful when generating new locations adjacent to the randomly generated one */
#define INC_LOC() __wrapcmp_program_loc++

/* Compare the `k`th byte of `a` and `b` and increment `v` by the number of common bits */
#define CK_BYTE(k, a, b, v) \
  do { v += count_zeros(BYTE##k(a) ^ BYTE##k(b)); } while(0)

/* Compare one byte of 8-bit operands `a` and `b`, and set value accordingly */
#define CMP_SET_8(a, b) \
  do { \
    uint32_t v = 0; \
    CK_BYTE(0, a, b, v); \
    WP(v); \
  } while(0)

/* Compare two bytes of 16-bit operands `a` and `b`, and set value accordingly */
#define CMP_SET_16(a, b) \
  do { \
    uint32_t v = 0; \
    CK_BYTE(0, a, b, v); \
    CK_BYTE(1, a, b, v); \
    WP(v); \
  } while(0)

/* Compare four bytes of 32-bit operands `a` and `b`, and set value accordingly */
#define CMP_SET_32(a, b) \
  do { \
    uint32_t v = 0; \
    CK_BYTE(0, a, b, v); \
    CK_BYTE(1, a, b, v); \
    CK_BYTE(2, a, b, v); \
    CK_BYTE(3, a, b, v); \
    WP(v); \
  } while(0)

/* Compare eight bytes of 64-bit operands `a` and `b`, and set value accordingly */
#define CMP_SET_64(a, b) \
  do { \
    uint32_t v = 0; \
    CK_BYTE(0, a, b, v); \
    CK_BYTE(1, a, b, v); \
    CK_BYTE(2, a, b, v); \
    CK_BYTE(3, a, b, v); \
    CK_BYTE(4, a, b, v); \
    CK_BYTE(5, a, b, v); \
    CK_BYTE(6, a, b, v); \
    CK_BYTE(7, a, b, v); \
    WP(v); \
  } while(0)

/* Compare `n` bytes of variable-length operands, and set value accordingly */
#define CMP_SET_N(a, b, n) \
 do { \
   uint32_t v = 0; \
   u8* op1 = (u8*) a; \
   u8* op2 = (u8*) b; \
   for (int i = 0; i < n; i++) { \
     v += count_zeros(op1[i] ^ op2[i]); \
   } \
   WP(v); \
 } while(0);

/* Compare `n` bytes of bounded-length string operands, and set value accordingly */
#define CMP_SET_N_STR(a, b, n) \
 do { \
   uint32_t v = 0; \
   char* op1 = (char*) a; \
   char* op2 = (char*) b; \
   for (int i = 0; i < n; i++) { \
     v += count_zeros(op1[i] ^ op2[i]); \
     if (!op1[i] || !op2[i]) break; \
   } \
   WP(v); \
 } while(0);

static uint32_t count_zeros (uint8_t byte)
{
  static const uint32_t NIBBLE_LOOKUP [16] =
  {
    4, 3, 3, 2, 3, 2, 2, 1, 
    3, 2, 2, 1, 2, 1, 1, 0
  };

  return NIBBLE_LOOKUP[byte & 0x0F] + NIBBLE_LOOKUP[byte >> 4];
}

bool __wrap_memcmp(void* s1, void* s2, size_t n);
bool __wrap_strncmp(char* s1, char* s2, size_t n);
bool __wrap_strcmp(char* s1, char* s2);
bool __wrap_strncasecmp(char* s1, char* s2, size_t n);
bool __wrap_strcasecmp(char* s1, char* s2);
char* __wrap_strstr(char* haystack, char* needle);
bool __wrap_eq8(int8_t a, int8_t b);
bool __wrap_eq16(int16_t a, int16_t b);
bool __wrap_eq32(int32_t a, int32_t b);
bool __wrap_eq64(int64_t a, int64_t b);
bool __wrap_neq8(int8_t a, int8_t b);
bool __wrap_neq16(int16_t a, int16_t b);
bool __wrap_neq32(int32_t a, int32_t b);
bool __wrap_neq64(int64_t a, int64_t b);
int8_t __wrap_switch_select8(int8_t op, uint32_t cases, ...);
int16_t __wrap_switch_select16(int16_t op, uint32_t cases, ...);
int32_t __wrap_switch_select32(int32_t op, uint32_t cases, ...);
int64_t __wrap_switch_select64(int64_t op, uint32_t cases, ...);

bool __wrap_eq8(int8_t a, int8_t b) {
  CMP_SET_8(a, b);
  WAYPOINTS_DEBUG("0x%02x == 0x%02x ?\n", a, b);
  return a == b;
}

bool __wrap_eq16(int16_t a, int16_t b) {
  CMP_SET_16(a, b);
  WAYPOINTS_DEBUG("0x%04x == 0x%04x ?\n", a, b);
  return a == b;
}

bool __wrap_eq32(int32_t a, int32_t b) {
  CMP_SET_32(a, b);
  WAYPOINTS_DEBUG("0x%08x == 0x%08x ?\n", a, b);
  return a == b;
}

bool __wrap_eq64(int64_t a, int64_t b) {
  CMP_SET_64(a, b);
  WAYPOINTS_DEBUG("0x%016lx == 0x%016lx ?\n", a, b);
  return a == b;
}

bool __wrap_neq8(int8_t a, int8_t b) {
  CMP_SET_8(a, b);
  WAYPOINTS_DEBUG("0x%02x != 0x%02x ?\n", a, b);
  return a != b;
}

bool __wrap_neq16(int16_t a, int16_t b) {
  CMP_SET_16(a, b);
  WAYPOINTS_DEBUG("0x%04x != 0x%04x ?\n", a, b);
  return a != b;
}

bool __wrap_neq32(int32_t a, int32_t b) {
  CMP_SET_32(a, b);
  WAYPOINTS_DEBUG("0x%08x != 0x%08x ?\n", a, b);
  return a != b;
}

bool __wrap_neq64(int64_t a, int64_t b) {
  CMP_SET_64(a, b);
  WAYPOINTS_DEBUG("0x%016lx != 0x%016lx ?\n", a, b);
  return a != b;
}

bool __wrap_memcmp(void* s1, void* s2, size_t n) {
  CMP_SET_N(s1, s2, n);
  WAYPOINTS_DEBUG("memcmp of size %zu\n", n);
  return memcmp(s1, s2, n);
}

bool __wrap_strncmp(char* s1, char* s2, size_t n) {
  CMP_SET_N_STR(s1, s2, n);
  WAYPOINTS_DEBUG("strncmp of size %zu: s1=%.*s, s2=%.*s\n", n, (int) n, s1, (int) n, s2);
  return strncmp(s1, s2, n);
}

bool __wrap_strcmp(char* s1, char* s2) {
  size_t l1 = strlen(s1);
  size_t l2 = strlen(s2);
  size_t max = l1 > l2 ? l1 : l2;
  CMP_SET_N_STR(s1, s2, max);
  WAYPOINTS_DEBUG("strcmp: s1=%s, s2=%s\n", s1, s2);
  return strcmp(s1, s2);
}

bool __wrap_strncasecmp(char* s1, char* s2, size_t n) {
  // Waypoints as if it was strncmp but return strncasecmp result
  CMP_SET_N_STR(s1, s2, n);
  WAYPOINTS_DEBUG("strncasecmp of size %zu: s1=%.*s, s2=%.*s\n", n, (int) n, s1, (int) n, s2);
  return strncasecmp(s1, s2, n);
}

bool __wrap_strcasecmp(char* s1, char* s2) {
  // Waypoints as if it was strcmp but return strcasecmp result
  size_t l1 = strlen(s1);
  size_t l2 = strlen(s2);
  size_t max = l1 > l2 ? l1 : l2;
  CMP_SET_N_STR(s1, s2, max);
  WAYPOINTS_DEBUG("strcasecmp: s1=%s, s2=%s\n", s1, s2);
  return strcasecmp(s1, s2);
}

char* __wrap_strstr(char* haystack, char* needle) {
  char* search_start = haystack;
  size_t needle_len = strlen(needle);
  char* haystack_end = haystack + strlen(haystack);
  while (search_start + needle_len <= haystack_end) {
    CMP_SET_N_STR(search_start, needle, needle_len);
    search_start++;
  }
  WAYPOINTS_DEBUG("strstr: haystack=%s needle=%s\n", haystack, needle);
  return strstr(haystack, needle);
}

int8_t __wrap_switch_select8(int8_t op, uint32_t cnt, ...) {
  WAYPOINTS_DEBUG("Switch on 0x%02x!\n", op);
  va_list args;
  va_start(args, cnt);
  for(int i = 0; i < cnt; i++) {\
    int c = va_arg(args, int);
    CMP_SET_8(op, c);
    WAYPOINTS_DEBUG(" - 0x%02x\n", c);
    INC_LOC();
  }
  va_end(args);
  return op;
}

int16_t __wrap_switch_select16(int16_t op, uint32_t cnt, ...) {
  WAYPOINTS_DEBUG("Switch on 0x%04x!\n", op);
  va_list args;
  va_start(args, cnt);
  for(int i = 0; i < cnt; i++) {\
    int c = va_arg(args, int);
    CMP_SET_16(op, c);
    WAYPOINTS_DEBUG(" - 0x%04x\n", c);
    INC_LOC();
  }
  va_end(args);
  return op;
}

int32_t __wrap_switch_select32(int32_t op, uint32_t cnt, ...) {
  WAYPOINTS_DEBUG("Switch on 0x%08x!\n", op);
  va_list args;
  va_start(args, cnt);
  for(int i = 0; i < cnt; i++) {\
    int32_t c = va_arg(args, int32_t);
    CMP_SET_32(op, c);
    WAYPOINTS_DEBUG(" - 0x%08x\n", c);
    INC_LOC();
  }
  va_end(args);
  return op;
}

int64_t __wrap_switch_select64(int64_t op, uint32_t cnt, ...) {
  WAYPOINTS_DEBUG("Switch on 0x%016lx!\n", op);
  va_list args;
  va_start(args, cnt);
  for(int i = 0; i < cnt; i++) {\
    int64_t c = va_arg(args, int64_t);
    CMP_SET_64(op, c);
    WAYPOINTS_DEBUG(" - 0x%016lx\n", c);
    INC_LOC();
  }
  va_end(args);
  return op;
}

