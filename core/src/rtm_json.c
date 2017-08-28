#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rtm_internal.h"

static int _rtm_isspace(int c) {
  // Use our own isspace() since ESP8266/Arduino have faulty implementations.
  // GCC and clang are smart enough to optimise the function away if a native
  // isspace() is available.
  return c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' || c == ' ';
}
#ifdef isspace
#undef isspace
#endif
#define isspace _rtm_isspace

/**
 * Escape a string such that it can be inserted into ".." as
 * valid json
 *
 * @param[in] dest Memory that will contain the escaped string
 * @param[in] n Maximal size of dest
 * @param[in] str String to be escaped
 * @return Pointer pointing to first position in dest after str, or NULL in
 *         case there isn't enough memory.
 */
char *_rtm_json_escape(char *dest, ssize_t n, const char *str) {
  if (n <= 0 || dest == NULL) {
    return NULL;
  }

  static const char toHex[] = "0123456789ABCDEF";
  const unsigned char *c = (unsigned char *)str;
  unsigned char *pb = (unsigned char *)dest;

  // preserve one char for \0
  size_t free_space = n - 1;
  while (*c) {
    if (*c == '\t') { // horizontal tab (0x09)
      if (free_space < 2) { return NULL; }
      free_space -= 2;
      *pb++ = '\\';
      *pb++ = 't';
    } else if (*c == '\r') { // carriage return (0x0d)
      if (free_space < 2) { return NULL; }
      free_space -= 2;
      *pb++ = '\\';
      *pb++ = 'r';
    } else if (*c == '\n') { // newline (0x0a)
      if (free_space < 2) { return NULL; }
      free_space -= 2;
      *pb++ = '\\';
      *pb++ = 'n';
    } else if (*c == '\f') { // formfeed (0x0c)
      if (free_space < 2) { return NULL; }
      free_space -= 2;
      *pb++ = '\\';
      *pb++ = 'f';
    } else if (*c == '\b') { // backspace (0x08)
      if (free_space < 2) { return NULL; }
      free_space -= 2;
      *pb++ = '\\';
      *pb++ = 'b';
    } else if (*c == '\\') { // reverse solidus (0x5c)
      if (free_space < 2) { return NULL; }
      free_space -= 2;
      *pb++ = '\\';
      *pb++ = '\\';
    } else if (*c == '"') { // quotation mark (0x22)
      if (free_space < 2) { return NULL; }
      free_space -= 2;
      *pb++ = '\\';
      *pb++ = '"';
    } else if (*c <= 0x1f) { // special characters [0..31]
      if (free_space < 6) { return NULL; }
      free_space -= 6;
      *pb++ = '\\';
      *pb++ = 'u';
      *pb++ = '0';
      *pb++ = '0';
      *pb++ = toHex[*c >> 4];
      *pb++ = toHex[*c & 0x0f];
    } else if (0x20 <= *(unsigned char*)c && *(unsigned char *)c <= 0x7f) { // ASCII
      if (free_space < 1) { return NULL; }
      free_space -= 1;
      *pb++ = *c;
    } else if ((*c & 0xe0) == 0xc0) { /* two bytes, UTF-8 unicode (110x xxxx) */
      if (free_space < 2) { return NULL; }
      if(!c[1]) continue; // Invalid UTF8, ignore character
      free_space -= 2;
      *pb++ = *c++;
      *pb++ = *c;
    } else if ((*c & 0xf0) == 0xe0) { /* three bytes, UTF-8 unicode (1110 xxxx) */
      if (free_space < 3) { return NULL; }
      if(!c[1] || !c[2]) continue; // Invalid UTF8, ignore character
      free_space -= 3;
      *pb++ = *c++;
      *pb++ = *c++;
      *pb++ = *c;
    } else if ((*c & 0xf8) == 0xf0) { /* four bytes, UTF-8 encode (1111 0xxx) */
      if (free_space < 4) { return NULL; }
      if(!c[1] || !c[2] || !c[3]) continue; // Invalid UTF8, ignore character
      free_space -= 4;
      *pb++ = *c++;
      *pb++ = *c++;
      *pb++ = *c++;
      *pb++ = *c;
    }

    ++c;
  }
  *pb = 0;

  return (char*)pb;
}

/**
 * Given a string starting at the beginning of a JSON value or token, determine
 * where it ends and return a pointer to the last character of said value/token.
 *
 * That is: For a string return a pointer to the closing quote, for an object return
 * a pointer to the closing brace, for a plain ":" or "," return the pointer that
 * was passed to this function, and so forth.
 *
 * @warning The behaviour of this function is undefined if json does not point to
 *          the beginning of a value/token
 * @warning This function assumes that the input is valid JSON, its behaviour is
 *          undefined JSON with improperly nested parentheses
 *
 * @param[in] p Pointer to the beginning of a JSON token
 * @return Pointer to the end of the given token, or NULL in case of invalid
 *         input
 */
static char *find_end_of_element(char *p) {
  char *json = p;
  int brackets = 0;
  char c;

  // Special case: If we are at a non-opening control character, return that
  // character
  if(*p == ',' || *p == ':' || *p == '}' || *p == ']') {
    return p;
  }

not_in_a_string:
  c = *json;
  ++json;
  if (c == '\0') {
    // Stream ended
    return brackets == 0 ? json - 1 : NULL;
  }
  if ((c == ',' || c == ':' || c == '}' || c == ']' || c == ' ')  && brackets == 0) {
    // At top level scope and this is a control character, so the previous
    // character closes the current token
    return json - 2 >= p ? json - 2 : NULL;
  }
  if (c == '{' || c == '[') {
    // Token starts an array or object
    ++brackets;
  } else if (c == ']' || c == '}') {
    // Token ends an array or object
    --brackets;
    if (brackets <= 0) {
      // This actually closed the outermost scope, so it closes the token
      // itself.
      return json - 1;
    }
  } else if (c == '\"') {
    // Token starts a string
    goto in_a_string;
  }
  goto not_in_a_string;

in_a_string:
  c = *json++;
  if (c == '\0')
    // Stream ended
    return NULL;
  if (c == '\\') {
    // Escaped character
    json++;
  } else if (c == '\"') {
    // String ended
    if (brackets == 0) {
      return json - 1;
    }
    goto not_in_a_string;
  }
  goto in_a_string;
}


/**
 * Find the next semantically meaningful element within a JSON structure.
 *
 * Example:
 *
 * \code{.c}
 * char *json = "\"foo\": \"bar\"}";
 * while(json && *json) {
 *   ssize_t length;
 *   char *next_element = _rtm_json_find_element(json, &json, &length);
 *   printf("%.*s\n", (int)length, json);
 *   json = next_element;
 * }
 * \endcode
 *
 * will output '"foo"', ':', '"bar"', and '}', on consecutive lines.
 *
 * @param[in] p A pointer into a JSON value/token
 * @param[out] cursor Will point to the beginning of the first value/token in p
 * @param[out] length Will contain the length of the value/token starting at cursor
 * @return Pointer to the next element in, or end of, p, or NULL in case of an error
 */
char *_rtm_json_find_element(char* p, char **cursor, size_t *length) {
  // Skip over any spaces preceding element
  while (isspace(*p)) p++;

  // Find the length of the element
  char *start = p;
  char *end = find_end_of_element(p);

  if (end == NULL || !*end) {
    // Invalid JSON
    *cursor = NULL;
    *length = 0;
    return NULL;
  }

  char *next_element = end + 1;
  while (isspace(*next_element)) {
    next_element++;
  }
  *cursor = start;
  if (length) {
      *length = end - start + 1;
  }

  return next_element;
}

static char _rtm_json_find_kv_pair_sentinel[] = "";

/**
 * Parse the next key/value pair out of a JSON object
 *
 * @param[in] p A pointer pointing to the start of a key definition inside an object
 * @param[out] key Will point to the start of the next key
 * @param[out] key Will contain the length of the next key
 * @param[out] key Will point to the start of the next value
 * @param[out] key Will contain the length of the next value
 * @return A pointer to the next key, or NULL at the end of the object
 *
 * If this function detects invalid JSON, key and value will be NULL. If it is
 * invoked on an empty object, key and value will point to an empty string.
 */
char *_rtm_json_find_kv_pair(char *p, char **key, size_t *key_length, char **value, size_t *value_length) {
  *key = NULL;
  *key_length = 0;
  *value = NULL;
  *value_length = 0;

  p = _rtm_json_find_element(p, key, key_length);

  if (!p || *p != ':') {
    *key_length = 0;
    if(*key && **key == '}') {
      // End of object
      *key = _rtm_json_find_kv_pair_sentinel;
      *value = _rtm_json_find_kv_pair_sentinel;
    }
    else {
      *key = NULL;
    }
    return NULL;
  }
  p++;
  if (!*p) {
    *key = NULL;
    *key_length = 0;
    return NULL;
  }

  p = _rtm_json_find_element(p, value, value_length);

  if(!p || (*p != ',' && *p != '}') || (*value && (**value == '}' || **value == ','))) {
    *key = NULL;
    *key_length = 0;
    *value = NULL;
    *value_length = 0;
    return NULL;
  }
  else if(*p == ',') {
    return p + 1;
  }
  else {
    return NULL;
  }
}

/**
 * Skip to the beginning of the next JSON object
 *
 * @param[in] p Pointer to a JSON stream
 * @return Pointer to the first character after the next "{", or NULL if none is found.
 */
char *_rtm_json_find_begin_obj(char *p) {
  while ((*p != '{') && isspace(*p)) {
    p++;
  }
  return (*p == '{') ? p+1 : NULL;
}
