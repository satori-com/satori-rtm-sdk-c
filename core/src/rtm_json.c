#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rtm_internal.h"

static char *find_end_of_element(char *json) {
  int brackets = 0;
  char c;

  not_in_a_string:
  c = *json++;
  if (c == '\0') {
    return json - 1;
  }
  if ((c == ',' || c == ']' || c == '}' || c == ':')  && brackets == 0) {
    return json - 1;
  }
  if (c == '{' || c == '[') {
    ++brackets;
  } else if (c == ']' || c == '}') {
    --brackets;
  } else if (c == '\"') {
    goto in_a_string;
  }
  goto not_in_a_string;

  in_a_string:
  c = *json++;
  if (c == '\0')
    return json - 1;
  if (c == '\\') {
    json++;
  } else if (c == '\"') {
    goto not_in_a_string;
  }
  goto in_a_string;
}

ssize_t _rtm_json_escape(char *dest, ssize_t n, const char *str) {
  if (n <= 0) {
    return 0;
  }

  static const unsigned char toHex[] = "0123456789ABCDEF";
  const unsigned char *c = (const unsigned char *) str;
  unsigned char *pb = (unsigned char *) dest;

  // preserve one char for \0
  ssize_t free_space = n - 1;
  while (*c) {
    if (*c == '\t') { // horizontal tab (0x09)
      free_space -= 2;
      if (free_space < 0) { break; }
      *pb++ = '\\';
      *pb++ = 't';
    } else if (*c == '\r') { // carriage return (0x0d)
      free_space -= 2;
      if (free_space < 0) { break; }
      *pb++ = '\\';
      *pb++ = 'r';
    } else if (*c == '\n') { // newline (0x0a)
      free_space -= 2;
      if (free_space < 0) { break; }
      *pb++ = '\\';
      *pb++ = 'n';
    } else if (*c == '\f') { // formfeed (0x0c)
      free_space -= 2;
      if (free_space < 0) { break; }
      *pb++ = '\\';
      *pb++ = 'f';
    } else if (*c == '\b') { // backspace (0x08)
      free_space -= 2;
      if (free_space < 0) { break; }
      *pb++ = '\\';
      *pb++ = 'b';
    } else if (*c == '\\') { // reverse solidus (0x5c)
      free_space -= 2;
      if (free_space < 0) { break; }
      *pb++ = '\\';
      *pb++ = '\\';
    } else if (*c == '"') { // quotation mark (0x22)
      free_space -= 2;
      if (free_space < 0) { break; }
      *pb++ = '\\';
      *pb++ = '"';
    } else if (0 <= *c && *c <= 0x1f) { // special characters [0..31]
      free_space -= 6;
      if (free_space < 0) { break; }
      *pb++ = '\\';
      *pb++ = 'u';
      *pb++ = '0';
      *pb++ = '0';
      *pb++ = toHex[*c >> 4];
      *pb++ = toHex[*c & 0x0f];
    } else if (0x20 <= *c && *c <= 0x7f) { // ASCII
      free_space -= 1;
      if (free_space < 0) { break; }
      *pb++ = *c;
    } else if ((*c & 0xe0) == 0xc0) { /* two bytes, UTF-8 unicode (110x xxxx) */
      free_space -= 2;
      if (free_space < 0) { break; }
      *pb++ = *c++;
      *pb++ = *c;
    } else if ((*c & 0xf0) == 0xe0) { /* three bytes, UTF-8 unicode (1110 xxxx) */
      free_space -= 3;
      if (free_space < 0) { break; }
      *pb++ = *c++;
      *pb++ = *c++;
      *pb++ = *c;
    } else if ((*c & 0xf8) == 0xf0) { /* four bytes, UTF-8 encode (1111 0xxx) */
      free_space -= 4;
      if (free_space < 0) { break; }
      *pb++ = *c++;
      *pb++ = *c++;
      *pb++ = *c++;
      *pb++ = *c;
    }

    ++c;
  }
  *pb = 0;

  if (free_space < 0) {
    return n;
  }
  return n - free_space - 1;
}

char *_rtm_json_find_element(char* p, char **cursor, ssize_t *length) {
  while (isspace(*p)) p++;
  char *start = p;
  char *next_element = find_end_of_element(p);
  char *end = next_element - 1;
  while (isspace(*next_element) || (',' == *next_element)) {
    next_element++;
  }
  while(end > start && isspace(*end)) {
    end--;
  }
  *cursor = start;
  if (length) {
      *length = end - start + 1;
  }
  return next_element;
}

char *_rtm_json_find_field_name(char* p, char **cursor, ssize_t *length) {
  char *ret = _rtm_json_find_element(p, cursor, length);
  while (isspace(*ret) || (':' == *ret)) {
    ret++;
  }
  return ret;
}

char *_rtm_json_find_begin_obj(char *p) {
  while ((*p != '{') && (*p != '\0')) {
    p++;
  }
  if ('{' == *p) { p++; }
  return p;
}
