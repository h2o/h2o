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

# usage: gen-bpf.py d_files_dir output_file

import re
import sys
from collections import OrderedDict
from pathlib import Path
from pprint import pprint

block_fields = {
    "quicly:crypto_decrypt": set(["decrypted"]),
    "quicly:receive": set(["bytes"]),
    "quicly:crypto_update_secret": set(["secret"]),
    "quicly:crypto_send_key_update": set(["secret"]),
    "quicly:crypto_receive_key_update": set(["secret"]),
    "quicly:crypto_receive_key_update_prepare": set(["secret"]),

    "h2o:h3_accept": set(["conn"]),  # `h2o_conn_t *conn`
}

quicly_block_probes = set([
    "quicly:debug_message",
])

h2o_allow_probes = set([
    "h2o:h3_accept",
    "h2o:h3_close",
    "h2o:send_response_header",
])

# convert field names for compatibility with:
# https://github.com/h2o/quicly/blob/master/quictrace-adapter.py
rename_map = {
    # common fields
    "at": "time",
    "master_id": "conn",

    # quicly_rtt_t
    "minimum": "min-rtt",
    "smoothed": "smoothed-rtt",
    "variance": "variance-rtt",
    "latest": "latest-rtt",
}

data_types_h = Path(Path(__file__).parent.parent, "data-types.h")

re_flags = re.X | re.M | re.S
whitespace = r'(?:/\*.*?\*/|\s+)'
probe_decl = r'(?:\bprobe\s+(?:[a-zA-Z0-9_]+)\s*\([^\)]*\)\s*;)'
d_decl = r'(?:\bprovider\s*(?P<provider>[a-zA-Z0-9_]+)\s*\{(?P<probes>(?:%s|%s)*)\})' % (
    probe_decl, whitespace)


def parse_c_struct(path):
  content = path.read_text()

  st_map = OrderedDict()
  for (st_name, st_content) in re.findall(r'struct\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}', content, flags=re_flags):
    st = st_map[st_name] = {}
    for (ctype, name, is_array) in re.findall(r'(\w+[^;]*[\w\*])\s+([a-zA-Z0-9_]+)(\[\d+\])?;', st_content, flags=re_flags):
      if "dummy" in name:
        continue
      st[name] = ctype + is_array
  return st_map


def parse_d(context: dict, path: Path, allow_probes: set = None, block_probes: set = None):
  content = path.read_text()

  matched = re.search(d_decl, content, flags=re_flags)
  provider = matched.group('provider')

  st_map = context["st_map"]
  probe_metadata = context["probe_metadata"]

  id = context["id"]

  for (name, args) in re.findall(r'\bprobe\s+([a-zA-Z0-9_]+)\(([^\)]+)\);', matched.group('probes'), flags=re_flags):
    arg_list = re.split(r'\s*,\s*', args, flags=re_flags)
    id += 1

    fully_specified_probe_name = "%s:%s" % (provider, name)
    if block_probes and fully_specified_probe_name in block_probes:
      continue
    if allow_probes and fully_specified_probe_name not in allow_probes:
      continue

    metadata = {
        "id": id,
        "provider": provider,
        "name": name,
        "fully_specified_probe_name": fully_specified_probe_name,
    }
    probe_metadata[name] = metadata
    args = metadata['args'] = list(map(
        lambda arg: re.match(
            r'(?P<type>\w[^;]*[^;\s])\s*\b(?P<name>[a-zA-Z0-9_]+)', arg, flags=re_flags).groupdict(),
        arg_list))

    flat_args_map = metadata['flat_args_map'] = OrderedDict()

    for arg in args:
      arg_name = arg['name']
      arg_type = arg['type']

      if is_ptr_type(arg_type) and not is_str_type(arg_type):
        for st_key, st_valtype in st_map[strip_typename(arg_type)].items():
          flat_args_map[st_key] = st_valtype
      else:
        flat_args_map[arg_name] = arg_type

  context["id"] = id


def strip_typename(t):
  return t.replace("*", "").replace("struct", "").replace("const", "").replace("strict", "").strip()


def is_str_type(t):
  return re.search(r'\b(?:char|u?int8_t|void)\s*\*', t)


def is_ptr_type(t):
  return "*" in t


def is_bin_type(t):
  return re.search(r'\b(?:u?int8_t|void)\s*\*', t)


def build_tracer_name(metadata):
  return "trace_%s__%s" % (metadata['provider'], metadata['name'])


def build_tracer(context, metadata):
  st_map = context["st_map"]
  fully_specified_probe_name = metadata["fully_specified_probe_name"]

  c = r"""// %s
int %s(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = %d };

""" % (fully_specified_probe_name, build_tracer_name(metadata), metadata['id'])
  block_field_set = block_fields.get(fully_specified_probe_name, set())
  probe_name = metadata["name"]

  args = metadata['args']
  for i in range(len(args)):
    arg = args[i]
    arg_name = arg['name']
    arg_type = arg['type']

    if arg_name in block_field_set:
      c += "  // %s %s (ignored)\n" % (arg_type, arg_name)
      continue
    else:
      c += "  // %s %s\n" % (arg_type, arg_name)

    if is_str_type(arg_type):
      c += "  bpf_usdt_readarg(%d, ctx, &buf);\n" % (i+1)
      # Use `sizeof(buf)` instead of a length variable, because older kernels
      # do not accept a variable for `bpf_probe_read()`'s length parameter.
      event_t_name = "%s.%s" % (probe_name, arg_name)
      c += "  bpf_probe_read(&event.%s, sizeof(event.%s), buf);\n" % (
          event_t_name, event_t_name)
    elif is_ptr_type(arg_type):
      c += "  %s %s = {};\n" % (arg_type.replace("*", ""), arg_name)
      c += "  bpf_usdt_readarg(%d, ctx, &buf);\n" % (i+1)
      c += "  bpf_probe_read(&%s, sizeof(%s), buf);\n" % (arg_name, arg_name)
      for st_key, st_valtype in st_map[strip_typename(arg_type)].items():
        event_t_name = "%s.%s" % (probe_name, st_key)
        c += "  event.%s = %s.%s; /* %s */\n" % (
            event_t_name, arg_name, st_key, st_valtype)
    else:
      event_t_name = "%s.%s" % (probe_name, arg_name)
      c += "  bpf_usdt_readarg(%d, ctx, &event.%s);\n" % (i +
                                                          1, event_t_name)

  if fully_specified_probe_name == "h2o:h3_accept":
    c += r"""
  h2o_to_quicly_conn.update(&event.h3_accept.conn_id, &event.h3_accept.master_id);
"""
  elif fully_specified_probe_name == "h2o:h3_close":
    c += r"""
  const uint32_t *master_conn_id_ptr = h2o_to_quicly_conn.lookup(&event.h3_close.conn_id);
  if (master_conn_id_ptr != NULL) {
    event.h3_close.master_id = *master_conn_id_ptr;
  } else {
    bpf_trace_printk("h2o's conn_id=%lu is not associated to master_conn_id\n", event.h3_close.conn_id);
  }
  h2o_to_quicly_conn.delete(&event.h3_close.conn_id);
"""
  elif metadata["provider"] == "h2o":
    c += r"""
  const uint32_t *master_conn_id_ptr = h2o_to_quicly_conn.lookup(&event.%s.conn_id);
  if (master_conn_id_ptr == NULL)
    return 0;
  event.%s.master_id = *master_conn_id_ptr;
""" % (probe_name, probe_name)
    if fully_specified_probe_name == "h2o:send_response_header":
      # handle -s option
      c += r"""
#ifdef CHECK_ALLOWED_RES_HEADER_NAME
  if (!CHECK_ALLOWED_RES_HEADER_NAME(event.send_response_header.name, event.send_response_header.name_len))
    return 0;
#endif
"""

  c += r"""
  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
"""
  return c

def prepare_context(d_files_dir):
  st_map = parse_c_struct(data_types_h)
  context = {
      "id": 0,
      "probe_metadata": OrderedDict(),
      "st_map": st_map,
  }
  parse_d(context, Path(d_files_dir, "quicly-probes.d"),
          block_probes=quicly_block_probes)
  parse_d(context, Path(d_files_dir, "h2o-probes.d"),
          allow_probes=h2o_allow_probes)

  return context


def generate_cplusplus(context, output_file):

  probe_metadata = context["probe_metadata"]

  event_t_decl = r"""
struct quic_event_t {
  uint8_t id;

  union {
"""

  for name, metadata in probe_metadata.items():
    event_t_decl += "    struct { // %s\n" % metadata["fully_specified_probe_name"]
    for field_name, field_type in metadata["flat_args_map"].items():
      if is_bin_type(field_type):
        f = "uint8_t %s[STR_LEN]" % field_name
      elif is_str_type(field_type):
        f = "char %s[STR_LEN]" % field_name
      else:
        f = "%s %s" % (field_type, field_name)

      event_t_decl += "      %s;\n" % f
    if metadata["provider"] == "h2o" and name != "h3_accept":
      event_t_decl += "      uint32_t master_id;\n"
    event_t_decl += "    } %s;\n" % name

  event_t_decl += r"""
    };
  };
  """

  bpf = r"""
#define STR_LEN 64
%s
%s
BPF_PERF_OUTPUT(events);

// HTTP/3 tracing
BPF_HASH(h2o_to_quicly_conn, u64, u32);
""" % (data_types_h.read_text(), event_t_decl)

  usdt_def = """
static
std::vector<ebpf::USDT> quic_init_usdt_probes(pid_t pid) {
  const std::vector<ebpf::USDT> probes = {
"""

  for metadata in probe_metadata.values():
    bpf += build_tracer(context, metadata)
    usdt_def += """    ebpf::USDT(pid, "%s", "%s", "%s"),\n""" % (
        metadata['provider'], metadata['name'], build_tracer_name(metadata))

  usdt_def += """
  };
  return probes;
}
"""

  handle_event_func = r"""
static
void quic_handle_event(h2o_tracer_t *tracer, const void *data, int data_len) {
  FILE *out = tracer->out;

  const quic_event_t *event = static_cast<const quic_event_t*>(data);

  // output JSON
  fprintf(out, "{");

  switch (event->id) {
"""

  for probe_name in probe_metadata:
    metadata = probe_metadata[probe_name]
    fully_specified_probe_name = metadata["fully_specified_probe_name"]

    block_field_set = block_fields.get(fully_specified_probe_name, None)
    flat_args_map = metadata["flat_args_map"]

    handle_event_func += "  case %s: { // %s\n" % (
        metadata['id'], fully_specified_probe_name)
    handle_event_func += '    json_write_pair(out, false, "type", "%s");\n' % probe_name.replace("_", "-")

    for field_name, field_type in flat_args_map.items():
      if block_field_set and field_name in block_field_set:
        continue
      json_field_name = rename_map.get(field_name, field_name).replace("_", "-")
      event_t_name = "%s.%s" % (probe_name, field_name)
      if not is_bin_type(field_type):
        handle_event_func += '    json_write_pair(out, true, "%s", event->%s);\n' % (
            json_field_name, event_t_name)
      else:  # bin type (it should have the correspinding length arg)
        len_names = set([field_name + "_len", "len"])

        for n in flat_args_map:
          if n in len_names:
            len_event_t_name = "%s.%s" % (probe_name, n)

        # A string might be truncated in STRLEN
        handle_event_func += '    json_write_pair(out, true, "%s", event->%s, (event->%s < STR_LEN ? event->%s : STR_LEN));\n' % (
            json_field_name, event_t_name, len_event_t_name, len_event_t_name)

    if metadata["provider"] == "h2o":
      if probe_name != "h3_accept":
        handle_event_func += '    json_write_pair(out, true, "master_conn_id", event->%s.master_id);\n' % (
            probe_name)
      handle_event_func += '    json_write_pair(out, true, "time", time_milliseconds());\n'

    handle_event_func += "    break;\n"
    handle_event_func += "  }\n"

  handle_event_func += r"""
  default:
    std::abort();
  }

  fprintf(out, "}\n");
"""
  handle_event_func += "}\n"

  Path(output_file).write_text(r"""// Generated code. Do not edit it here!

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include "h2olog.h"
#include "data-types.h"
#include "json.h"

#define STR_LEN 64

// BPF modules written in C
const char *bpf_text = R"(
%s
)";

static uint64_t time_milliseconds()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

%s
%s
%s

static void quic_handle_lost(h2o_tracer_t *tracer, uint64_t lost) {
  fprintf(tracer->out, "{\"type\":\"h2olog-event-lost\",\"time\":%%" PRIu64 ",\"lost\":%%" PRIu64 "}\n", time_milliseconds(), lost);
}

static const char *quic_bpf_ext() {
  return bpf_text;
}

void init_quic_tracer(h2o_tracer_t * tracer) {
  tracer->handle_event = quic_handle_event;
  tracer->handle_lost = quic_handle_lost;
  tracer->init_usdt_probes = quic_init_usdt_probes;
  tracer->bpf_text = quic_bpf_ext;
}

""" % (bpf, usdt_def, event_t_decl, handle_event_func))


def main():
  try:
    (_, d_files_dir, output_file) = sys.argv
  except:
    print("usage: %s d_files_dir output_file" % sys.argv[0])
    sys.exit(1)

  context = prepare_context(d_files_dir)
  generate_cplusplus(context, output_file)


if __name__ == "__main__":
  main()
