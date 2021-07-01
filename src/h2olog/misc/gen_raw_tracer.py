#!/usr/bin/env python3
#
# Copyright (c) 2019-2020 Fastly, Inc., Toru Maesaka, Goro Fuji
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

# gen_raw_tracer.py - Generate an h2olog tracer to emit USDT probes by parsing D script files.
#
# gen_raw_tracer.py parses D script files accompanied by @appdata annotation, for example:
#
# <code>
# /* @appdata
#  {
#     "probe1": ["payload1", "payload2"]
#  }
#  */
# provider provider1 {
#   probe probe1(const char *payload1, void *payload2, size_t payload2_len);
# }
# </code>
#
# In this case, `payload1` and `payload2` are annotated as application data,
# which h2olog does not emit by default.

import re
import sys
import json
import os
from typing import Optional, Tuple, Any
from collections import OrderedDict
from pathlib import Path
from pprint import pprint
from copy import deepcopy

DEBUG = os.getenv("DEBUG")

quicly_probes_d = "deps/quicly/quicly-probes.d"
h2o_probes_d = "h2o-probes.d"

# An allow-list to gather data from USDT probes.
# Only fields listed here are handled in BPF.
struct_map = OrderedDict([
    # deps/quicly/include/quicly.h
    ["st_quicly_stream_t", [
        # ($member_access, $optional_flat_name)
        # If $optional_flat_name is None, $member_access is used.
        ("stream_id", None),
    ]],

    # deps/quicly/include/quicly/loss.h
    ["quicly_rtt_t", [
        ("minimum", None),
        ("smoothed", None),
        ("variance", None),
        ("latest",  None),
    ]],

    # deps/quicly/lib/quicly.c
    ["st_quicly_conn_t", [
        ("super.local.cid_set.plaintext.master_id", "master_id"),
    ]],

    ["st_h2o_ebpf_map_key_t", []],

    ["sockaddr", []],
    ["sockaddr_in", []],
    ["sockaddr_in6", []],
])

# The block list for probes.
# All the probes are handled by default in JSON mode
block_probes = set([
    "quicly:debug_message",
])

# To rename field names for compatibility with:
# https://github.com/h2o/quicly/blob/master/quictrace-adapter.py
rename_map = {
    # common fields
    "at": "time",
    "conn_master_id": "conn",

    # changed in the latest quicly master branch
    "num_bytes": "bytes_len",

    # quicly_rtt_t
    "rtt_minimum": "min-rtt",
    "rtt_smoothed": "smoothed-rtt",
    "rtt_variance": "variance-rtt",
    "rtt_latest": "latest-rtt",

    # quicly_stream_t
    "stream_stream_id": "stream_id",
}

st_quicly_conn_t_def = r"""
// This is enough for here. See `quicly.c` for the full definition.
struct st_quicly_conn_t {
  struct _st_quicly_conn_public_t super;
};
"""

re_xms = re.X | re.M | re.S
comment = r'/\*.*?\*/'


class Lexer:

  def __init__(self, src: str, filename: Optional[str] = None):
    self.src = src
    self.filename = filename
    self.pos = 0

  def skip(self, pattern) -> bool:
    m = re.match(pattern, self.src[self.pos:], re_xms)
    if m:
      self.pos += m.end()
      return True
    return False

  def skip_whitespaces(self) -> bool:
    return self.skip(r'\s+')

  def skip_whitespaces_or_comments(self):
    while self.skip_whitespaces() or self.skip(comment):
      pass

  def expect_opt(self, pattern):
    m = re.match(pattern, self.src[self.pos:], re_xms)
    if m:
      self.pos += m.end()
    return m

  def expect(self, pattern):
    m = self.expect_opt(pattern)
    if not m:
      sys.exit("Expected '%s' but got '%s' %s"
               % (pattern, self.src[self.pos], self.position_hint()))
    return m

  def peek(self, pattern):
    return re.match(pattern, self.src[self.pos:], re_xms)

  def position_hint(self):
    if self.filename:
      return "at %s:%s" % (self.filename, self.line_and_column())
    else:
      return "at %s" % self.line_and_column()

  def line_and_column(self):
    lines = re.split(r'\n', self.src[:self.pos])
    return "%d:%d" % (len(lines), len(lines[-1]))


def parse_dscript(path: Path):
  lexer = Lexer(path.read_text(), path.name)

  provider = None  # type: Optional[str]
  probes = OrderedDict()
  appdata = None

  def die(msg):
    sys.exit("[dscript-parser] %s %s" % (msg, lexer.position_hint()))

  # before the "provider" keyword
  prev_pos = -1
  while prev_pos != lexer.pos:
    prev_pos = lexer.pos

    while True:
      lexer.skip_whitespaces()
      m = lexer.expect_opt(comment)
      if m:
        # find for /* @appdata {...} */
        m = re.match(r'/\*\s*@appdata\s*(?P<json>\{.*\})\s*\*/', m.group(0), re_xms)
        if m:
          if appdata:
            die("cannot place @appdata annotation more than once per file")
          try:
            appdata = json.loads(m.group("json"))
          except:
            die("cannot parse JSON in the @appdata annotation")
          if not isinstance(appdata, dict):
            die("@appdata must be a JSON object")
      else:
        break

    lexer.skip_whitespaces_or_comments()
    if lexer.peek(r'provider\b'):
      break
    # ignore anythong other than the "provider" keyword
    lexer.skip(r'\S+')

  # a provider block
  m = lexer.expect(r'provider\s+(?P<provider>\w+)\s*\{')
  provider = m.group("provider")

  # list of probes
  while True:
    lexer.skip_whitespaces_or_comments()

    m = lexer.expect_opt(r'probe\s+(?P<probe>\w+)\s*\(')
    if m:
      probe_name = m.group("probe")
      probe = {
          "name": probe_name,
          "args": [],
      }

      probes[probe_name] = probe

      # list of fields or parameters
      while True:
        lexer.skip_whitespaces()

        tokens = []  # type: list[str]
        while True:
          lexer.skip_whitespaces_or_comments()
          m = lexer.expect_opt(r'\w+|\*')
          if m:
            tokens.append(m.group(0))
          else:
            break

        name = tokens.pop()

        arg = {
            "name": name,
            "type": " ".join(tokens),
        }
        probe["args"].append(arg)

        lexer.skip_whitespaces_or_comments()
        m = lexer.expect_opt(r',')
        if not m:
          break

      lexer.skip_whitespaces_or_comments()
      lexer.expect(r'\)')
      lexer.skip_whitespaces_or_comments()
      lexer.expect(r';')
    else:
      break

  lexer.skip_whitespaces_or_comments()
  lexer.expect(r'}')

  return {
      "provider": provider,
      "probes": probes,
      "appdata": appdata,
  }

def parse_and_analyze(context: dict, d_file: Path):
  dscript = parse_dscript(d_file)

  if DEBUG:
    json.dump(dscript, sys.stderr, indent=2)
    print("", file=sys.stderr)

  if dscript["appdata"] == None:
    sys.exit("@appdata section is not declared in %s" % d_file)

  provider = dscript["provider"]
  appdata = deepcopy(dscript["appdata"])  # type: dict[str, Any]

  probe_metadata = context["probe_metadata"]

  for (name, probe) in dscript["probes"].items():
    id = ("H2OLOG_EVENT_ID_%s_%s" % (provider, name)).upper()

    fully_specified_probe_name = "%s:%s" % (provider, name)
    if block_probes and fully_specified_probe_name in block_probes:
      continue

    metadata = {
        "id": id,
        "provider": provider,
        "name": name,
        "args": probe["args"],
        "fully_specified_probe_name": fully_specified_probe_name,
        "appdata_field_set": set(),
    }
    probe_metadata[name] = metadata
    args = metadata['args']

    appdata_fields = appdata.get(name, None)
    if appdata_fields != None:
      if not isinstance(appdata_fields, list):
        sys.exit("An @appdata field must have a list of strings as a value but got: %s" % json.dumps(appdata_fields))
    else:
      appdata_fields = []

    flat_args_map = metadata['flat_args_map'] = OrderedDict()
    for arg in args:
      arg_name = arg['name']
      arg_type = arg['type']

      if arg_name in appdata_fields:
        appdata_fields.remove(arg_name)
        metadata["appdata_field_set"].add(arg_name)

      if is_ptr_type(arg_type):
        st_name = strip_typename(arg_type)
        if st_name in struct_map:
          if struct_map[st_name]:
            # decodes the struct into members in BPF programs.
            for st_field_access, st_field_name in struct_map[st_name]:
              flat_arg_name = "%s_%s" % (arg_name, st_field_name or st_field_access)
              flat_args_map[flat_arg_name] = "typeof_%s__%s" % (st_name, st_field_name or st_field_access)
          else:
            # decodes the struct into members in the user space (json.cc).
            flat_args_map[arg_name] = "struct %s" % st_name
        else:
          flat_args_map[arg_name] = arg_type
      else:
        flat_args_map[arg_name] = arg_type

    if name in appdata and len(appdata_fields) == 0:
      del appdata[name]

  # make sure all the items in @appdata have been consumed
  if appdata:
    for (probe_name, fields) in appdata.items():
      if fields:
        print("invalid @appdata: probe fields are not used in provider %s: %s: %s" %
              (provider, json.dumps(probe_name), json.dumps(fields)), file=sys.stderr)
      else:
        print("invalid @appdata: probe name is not used in provider %s: %s" %
              (provider, json.dumps(probe_name)), file=sys.stderr)
    sys.exit(1)


def strip_typename(t):
  return t.replace("*", "").replace("struct", "").replace("const", "").replace("strict", "").strip()


def is_str_type(t):
  return re.search(r'\b(?:char)\s*\*', t)


def is_bin_type(t):
  return re.search(r'\b(?:u?int8_t|void)\s*\*', t)


def is_sockaddr(t):
  return re.search(r'\b(?:sockaddr|quicly_address_t)\s*\*', t)


def is_ptr_type(t):
  return "*" in t and not (is_str_type(t) or is_bin_type(t) or is_sockaddr(t))


def build_tracer_name(metadata):
  return "trace_%s__%s" % (metadata['provider'], metadata['name'])


def build_tracer(context, metadata):
  fully_specified_probe_name = metadata["fully_specified_probe_name"]
  tracer_name = build_tracer_name(metadata)
  c = r"""// %s
int %s(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = %s, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

""" % (fully_specified_probe_name, tracer_name, metadata['id'])
  appdata_field_set = metadata["appdata_field_set"]  # type: set[str]
  probe_name = metadata["name"]

  args = metadata['args']
  for i in range(len(args)):
    arg = args[i]
    arg_name = arg['name']
    arg_type = arg['type']

    if arg_name in appdata_field_set:
      c += "  // %s %s (appdata)\n" % (arg_type, arg_name)
    else:
      c += "  // %s %s\n" % (arg_type, arg_name)

    if is_str_type(arg_type) or is_bin_type(arg_type):
      c += "  bpf_usdt_readarg(%d, ctx, &buf);\n" % (i+1)
      # Use `sizeof(buf)` instead of a length variable, because older kernels
      # do not accept a variable for `bpf_probe_read()`'s length parameter.
      event_t_name = "%s.%s" % (probe_name, arg_name)
      c += "  bpf_probe_read(&event.%s, sizeof(event.%s), buf);\n" % (
          event_t_name, event_t_name)
    elif is_sockaddr(arg_type):
      c += "  bpf_usdt_readarg(%d, ctx, &buf);\n" % (i+1)
      event_t_name = "%s.%s" % (probe_name, arg_name)
      c += "  bpf_probe_read(&event.%s, sizeof_sockaddr, buf);\n" % event_t_name
      c += "  if (get_sockaddr__sa_family(&event.%s) == AF_INET) {\n" % event_t_name
      c += "    bpf_probe_read(&event.%s, sizeof_sockaddr_in, buf);\n" % event_t_name
      c += "  } else if (get_sockaddr__sa_family(&event.%s) == AF_INET6) {\n" % event_t_name
      c += "    bpf_probe_read(&event.%s, sizeof_sockaddr_in6, buf);\n" % event_t_name
      c += "  }\n"
    elif is_ptr_type(arg_type):
      st_name = strip_typename(arg_type)
      if st_name in struct_map:
        if struct_map[st_name]:
          c += "  uint8_t %s[sizeof_%s] = {};\n" % (arg_name, st_name)
          c += "  bpf_usdt_readarg(%d, ctx, &buf);\n" % (i+1)
          c += "  bpf_probe_read(&%s, sizeof_%s, buf);\n" % (arg_name, st_name)
          for st_field_access, st_field_name in struct_map[st_name]:
            event_t_name = "%s.%s_%s" % (probe_name, arg_name, st_field_name or st_field_access)
            c += "  event.%s = get_%s__%s(%s);\n" % (
                event_t_name, st_name, st_field_name or st_field_access, arg_name)
        else:
          c += "  bpf_usdt_readarg(%d, ctx, &buf);\n" % (i+1)
          c += "  bpf_probe_read(&event.%s.%s, sizeof_%s, buf);\n" % (probe_name, arg_name, st_name)
      else:
        c += "  bpf_usdt_readarg(%d, ctx, &event.%s.%s);\n" % (i + 1, probe_name, arg_name)
    else:
      c += "  bpf_usdt_readarg(%d, ctx, &event.%s.%s);\n" % (i + 1, probe_name, arg_name)
  if fully_specified_probe_name == "h2o:send_response_header":
      # handle -s option
    c += r"""
#ifdef CHECK_ALLOWED_RES_HEADER_NAME
  if (!CHECK_ALLOWED_RES_HEADER_NAME(event.send_response_header.name, event.send_response_header.name_len))
    return 0;
#endif
"""

  if fully_specified_probe_name == "h2o:_private_socket_lookup_flags":
    c += r"""
  uint64_t flags = event._private_socket_lookup_flags.original_flags;
#ifdef H2OLOG_SAMPLING_RATE_U32
  if ((flags & H2O_EBPF_FLAGS_SKIP_TRACING_BIT) == 0) {
    if (bpf_get_prandom_u32() >= H2OLOG_SAMPLING_RATE_U32)
      flags |= H2O_EBPF_FLAGS_SKIP_TRACING_BIT;
  }
#endif
#ifdef H2OLOG_IS_SAMPLING_ADDRESS
  if ((flags & H2O_EBPF_FLAGS_SKIP_TRACING_BIT) == 0) {
    if (!H2OLOG_IS_SAMPLING_ADDRESS(event._private_socket_lookup_flags.info.family,
                                    event._private_socket_lookup_flags.info.remote.ip))
      flags |= H2O_EBPF_FLAGS_SKIP_TRACING_BIT;
  }
#endif
  int64_t ret = h2o_return.insert(&event._private_socket_lookup_flags.tid, &flags);
  if (ret != 0)
    bpf_trace_printk("failed to insert 0x%%llx in %s with errno=%%lld\n", flags, -ret);
""" % (tracer_name)
  elif fully_specified_probe_name == "h2o:_private_socket_lookup_flags_sni":
    c+= r"""
  uint64_t flags  = event._private_socket_lookup_flags_sni.original_flags;
  if ((flags & H2O_EBPF_FLAGS_SKIP_TRACING_BIT) != 0) {
#ifdef H2OLOG_IS_SAMPLING_SNI
    size_t server_name_len = event._private_socket_lookup_flags_sni.server_name_len;
    if (server_name_len > sizeof(event._private_socket_lookup_flags_sni.server_name))
      server_name_len = sizeof(event._private_socket_lookup_flags_sni.server_name);
    if (H2OLOG_IS_SAMPLING_SNI(event._private_socket_lookup_flags_sni.server_name, server_name_len)
#ifdef H2OLOG_SAMPLING_RATE_U32
        && bpf_get_prandom_u32() < H2OLOG_SAMPLING_RATE_U32
#endif
      )
      flags &= ~H2O_EBPF_FLAGS_SKIP_TRACING_BIT;
#endif
  }
  int64_t ret = h2o_return.insert(&event._private_socket_lookup_flags_sni.tid, &flags);
  if (ret != 0)
    bpf_trace_printk("failed to insert 0x%%lx in %s with errno=%%lld\n", flags, -ret);
""" % (tracer_name)
  else:
    c += r"""
  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in %s\n");
""" % (tracer_name)

  c += r"""
  return 0;
}
"""

  if fully_specified_probe_name.startswith("h2o:_private_socket_lookup_flags"):
    c = r"""
#if H2OLOG_SELECTIVE_TRACING
%s
#endif

""" % c.strip()

  return c


def prepare_context(d_files: list):
  context = {
      "probe_metadata": OrderedDict(),
  }
  for d_file in d_files:
    parse_and_analyze(context, Path(d_file))
  return context


def build_bpf_header_generator():
  generator = r"""
#define GEN_FIELD_INFO(type, field, name) gen_field_info(#type, #field, &((type *)NULL)->field, name)

#define DEFINE_RESOLVE_FUNC(field_type) \
std::string gen_field_info(const char *struct_type, const char *field_name, const field_type *field_ptr, const char *name) \
{ \
    return do_resolve(struct_type, field_name, #field_type, field_ptr, name); \
}

template <typename FieldType>
static std::string do_resolve(const char *struct_type, const char *field_name, const char *field_type, const FieldType *field_ptr, const char *name) {
    char *buff = NULL;
    size_t buff_len = 0;
    FILE *mem = open_memstream(&buff, &buff_len);
    fprintf(mem, "/* %s (%s#%s) */\n", name, struct_type, field_name);
    fprintf(mem, "#define offsetof_%s %zd\n", name, (const char *)field_ptr - (const char *)NULL);
    fprintf(mem, "#define typeof_%s %s\n", name, field_type);
    fprintf(mem, "#define get_%s(st) *((const %s *) ((const char*)st + offsetof_%s))\n", name, field_type, name);
    fprintf(mem, "\n");
    fflush(mem);
    std::string s(buff, buff_len);
    fclose(mem);
    return s;
}

DEFINE_RESOLVE_FUNC(int16_t);
DEFINE_RESOLVE_FUNC(uint16_t);
DEFINE_RESOLVE_FUNC(int32_t);
DEFINE_RESOLVE_FUNC(uint32_t);
DEFINE_RESOLVE_FUNC(int64_t);
DEFINE_RESOLVE_FUNC(uint64_t);

static std::string gen_bpf_header() {
  std::string bpf;
"""

  for st_name, st_fields in struct_map.items():
    # It limits a size of structs to 100 as a heuristic.
    # This is because the BPF stack has a limit to 512 bytes.
    generator += r"""
  bpf += "#define sizeof_%s " + std::to_string(std::min<size_t>(sizeof(struct %s), 100)) + "\n";
""" % (st_name, st_name)

    for st_field_access, st_field_name_alias in st_fields:
      name = "%s__%s" % (st_name, st_field_name_alias or st_field_access)
      generator += """  bpf += GEN_FIELD_INFO(struct %s, %s, "%s");\n""" % (st_name, st_field_access, name)

  generator += r"""
  bpf += GEN_FIELD_INFO(struct sockaddr, sa_family, "sockaddr__sa_family");
  bpf += "#define AF_INET  " + std::to_string(AF_INET) + "\n";
  bpf += "#define AF_INET6 " + std::to_string(AF_INET6) + "\n";
"""

  generator += r"""
  return bpf;
}
"""
  return generator


def build_typedef_for_cplusplus():
  typedef = st_quicly_conn_t_def

  for st_name, st_fields in struct_map.items():
    for st_field_access, st_field_name_alias in st_fields:
      typedef += """using typeof_%s__%s = decltype(%s::%s);\n""" % (st_name, st_field_name_alias or st_field_access, st_name, st_field_access)

  return typedef


def generate_cplusplus(context, output_file):
  probe_metadata = context["probe_metadata"]

  event_id_t_decl = r"""
enum h2olog_event_id_t {
  H2OLOG_EVENT_ID_SCHED_SCHED_PROCESS_EXIT,
"""

  event_t_decl = r"""
struct h2olog_event_t {
  enum h2olog_event_id_t id;
  uint32_t tid;

  union {
"""

  for name, metadata in probe_metadata.items():
    fully_specified_probe_name = metadata["fully_specified_probe_name"]
    appdata_field_set = metadata["appdata_field_set"]
    event_id_t_decl += "  %s,\n" % metadata["id"]

    event_t_decl += "    struct { // %s\n" % fully_specified_probe_name
    for field_name, field_type in metadata["flat_args_map"].items():
      if is_bin_type(field_type):
        f = "uint8_t %s[STR_LEN]" % field_name
      elif is_str_type(field_type):
        f = "char %s[STR_LEN]" % field_name
      elif is_sockaddr(field_type):
        f = "quicly_address_t %s" % field_name
      else:
        f = "%s %s" % (field_type, field_name)

      if field_name in appdata_field_set:
        event_t_decl += "      %s; // appdata\n" % f
      else:
        event_t_decl += "      %s;\n" % f
    event_t_decl += "    } %s;\n" % name

  event_t_decl += r"""
  };
};
"""

  event_id_t_decl += "};\n"

  bpf = r"""
#include <linux/sched.h>
#include <linux/limits.h>
#include "h2o/ebpf.h"

#define STR_LEN 64

typedef union quicly_address_t {
  uint8_t sa[sizeof_sockaddr];
  uint8_t sin[sizeof_sockaddr_in];
  uint8_t sin6[sizeof_sockaddr_in6];
} quicly_address_t;

%s
%s
BPF_PERF_OUTPUT(events);

// HTTP/3 tracing
BPF_HASH(h2o_to_quicly_conn, u64, u32);

#if H2OLOG_SELECTIVE_TRACING
// A pinned BPF object to return a value to h2o.
// The table size must be larger than the number of threads in h2o.
BPF_TABLE_PINNED("lru_hash", pid_t, uint64_t, h2o_return, H2O_EBPF_RETURN_MAP_SIZE, H2O_EBPF_RETURN_MAP_PATH);
#endif

// tracepoint sched:sched_process_exit
int trace_sched_process_exit(struct tracepoint__sched__sched_process_exit *ctx) {
  const struct task_struct *task = (const struct task_struct*)bpf_get_current_task();
  pid_t h2o_pid = task->tgid;
  pid_t h2o_tid = task->pid;
  if (!(h2o_pid == H2OLOG_H2O_PID && h2o_tid == H2OLOG_H2O_PID)) {
    return 0;
  }
  struct h2olog_event_t ev = { .id = H2OLOG_EVENT_ID_SCHED_SCHED_PROCESS_EXIT };
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}

""" % (event_id_t_decl, event_t_decl)

  usdts_def = r"""
void h2o_raw_tracer::initialize() {
  available_usdts.assign({
"""
  for metadata in probe_metadata.values():
    bpf += build_tracer(context, metadata)

    if metadata["fully_specified_probe_name"].startswith("h2o:_private_socket_lookup_flags"):
      continue
    usdts_def += """    h2o_tracer::usdt("%s", "%s", "%s"),\n""" % (
        metadata['provider'], metadata['name'], build_tracer_name(metadata))
  usdts_def += r"""
  });
}
"""

  handle_event_func = r"""
void h2o_raw_tracer::do_handle_event(const void *data, int data_len) {
  const h2olog_event_t *event = static_cast<const h2olog_event_t*>(data);

  if (event->id == H2OLOG_EVENT_ID_SCHED_SCHED_PROCESS_EXIT) {
    exit(0);
  }

  // output JSON
  fprintf(out_, "{");

  switch (event->id) {
"""

  for probe_name in probe_metadata:
    metadata = probe_metadata[probe_name]
    fully_specified_probe_name = metadata["fully_specified_probe_name"]

    if fully_specified_probe_name == "h2o:_private_socket_lookup_flags":
      continue

    appdata_field_set = metadata["appdata_field_set"]  # type: set[str]
    flat_args_map = metadata["flat_args_map"]

    handle_event_func += "  case %s: { // %s\n" % (
        metadata['id'], fully_specified_probe_name)
    handle_event_func += '    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("%s"));\n' % probe_name.replace("_", "-")
    handle_event_func += '    json_write_pair_c(out_, STR_LIT("tid"), event->tid);\n'
    handle_event_func += '    json_write_pair_c(out_, STR_LIT("seq"), seq_);\n'

    for field_name, field_type in flat_args_map.items():
      stmts = ""
      json_field_name = rename_map.get(field_name, field_name).replace("_", "-")
      event_t_name = "%s.%s" % (probe_name, field_name)
      if not is_bin_type(field_type) and not is_str_type(field_type):
        stmts += '    json_write_pair_c(out_, STR_LIT("%s"), event->%s);\n' % (
            json_field_name, event_t_name)
      else:  # bin or str type with "*_len" field
        len_names = set([field_name + "_len", "num_" + field_name])

        len_event_t_name = None
        for n in flat_args_map:
          if n in len_names:
            len_event_t_name = "%s.%s" % (probe_name, n)

        if len_event_t_name:
          # A string might be truncated in STRLEN
          stmts += '    json_write_pair_c(out_, STR_LIT("%s"), event->%s, (event->%s < STR_LEN ? event->%s : STR_LEN));\n' % (
              json_field_name, event_t_name, len_event_t_name, len_event_t_name)
        elif is_bin_type(field_type):
          stmts += '    # warning "missing `%s_len` param in the probe %s, ignored."\n' % (
              field_name, fully_specified_probe_name)
        else:  # str type
          stmts += '    json_write_pair_c(out_, STR_LIT("%s"), event->%s, strlen(event->%s));\n' % (
              json_field_name, event_t_name, event_t_name)
      if field_name in appdata_field_set:
        handle_event_func += "    if (include_appdata_) {\n"
        handle_event_func += re.sub(r"^", "  ", stmts, flags=re_xms).rstrip() + "\n"
        handle_event_func += "    }\n"
      else:
        handle_event_func += stmts

    if metadata["provider"] == "h2o":
      handle_event_func += '    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());\n'

    handle_event_func += "    break;\n"
    handle_event_func += "  }\n"

  handle_event_func += r"""
  default:
    std::abort();
  }

  fprintf(out_, "}\n");
"""
  handle_event_func += "}\n"

  Path(output_file).write_text(r"""// Generated code. Do not edit it here!

extern "C" {
#include <sys/time.h>
#include "quicly.h"
#include "h2o/ebpf.h"
}

#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <algorithm>

#include "h2olog.h"
#include "json.h"

#include "raw_tracer.cc.h"

#define STR_LEN 64
#define STR_LIT(s) s, strlen(s)

using namespace std;

%s
%s
%s
%s
%s
%s

std::string h2o_raw_tracer::bpf_text() {
  // language=c
  return gen_bpf_header() + R"(
%s
)";
}

""" % (build_typedef_for_cplusplus(), build_bpf_header_generator(), event_id_t_decl, event_t_decl, usdts_def, handle_event_func, bpf))


def usage():
  print("usage: %s output_file d_files..." % sys.argv[0])
  sys.exit(1)


def main():
  if len(sys.argv) <= 2:
    usage()

  output_file, *d_files = sys.argv[1:]

  context = prepare_context(d_files)
  generate_cplusplus(context, output_file)


if __name__ == "__main__":
  main()
