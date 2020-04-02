#include "json.h"

static void json_write_str_value(std::ostream &out, const char* str) {
  out << '"';
  while(*str) {
    switch(*str) {
    case '\"': out << "\\\""; break;
    case '\\': out << "\\\\"; break;
    case '\b': out << "\\b";  break;
    case '\f': out << "\\f";  break;
    case '\n': out << "\\n";  break;
    case '\r': out << "\\r";  break;
    case '\t': out << "\\t";  break;
    default  : out << *str; break;
    }
    str++;
  }
  out << '"';
}

void json_write_pair(std::ostream &out, bool comma, const char* name, const char* value) {
  if (comma) {
    out << ",";
  }
  json_write_str_value(out, name);
  out << ":";
  json_write_str_value(out, value);
}

void json_write_pair(std::ostream &out, bool comma, const char* name, const void* value, std::size_t len) {
  if (comma) {
    out << ",";
  }
  json_write_str_value(out, name);
  out << ":";
  out << '"';
  const std::uint8_t *bin = static_cast<const std::uint8_t *>(value);
  for (std::size_t i = 0; i < len; i++) {
    out << "0123456789abcdef"[bin[i] >> 4];
    out << "0123456789abcdef"[bin[i] & 0xf];
  }
  out << '"';
}

void json_write_pair(std::ostream &out, bool comma, const char* name, const std::int32_t value) {
  json_write_pair(out, comma, name, (std::int64_t)value);
}

void json_write_pair(std::ostream &out, bool comma, const char* name, const std::uint32_t value) {
  json_write_pair(out, comma, name, (std::uint64_t)value);
}

void json_write_pair(std::ostream &out, bool comma, const char* name, const std::int64_t value) {
  if (comma) {
    out << ",";
  }
  json_write_str_value(out, name);
  out << ":" << value;
}

void json_write_pair(std::ostream &out, bool comma, const char* name, const std::uint64_t value) {
  if (comma) {
    out << ",";
  }
  json_write_str_value(out, name);
  out << ":" << value;
}
