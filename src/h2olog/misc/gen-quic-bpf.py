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

# usage: gen-quic-bpf.py h2o_dir output_file

import re
import sys
from collections import OrderedDict
from pathlib import Path
from pprint import pprint

quicly_probes_d = "deps/quicly/quicly-probes.d"
h2o_probes_d = "h2o-probes.d"

# An allow-list to gather data from USDT probes.
# Only fields listed here are handled in BPF.
struct_map = {
    # deps/quicly/include/quicly.h
    "st_quicly_stream_t": [
        # ($member_access, $optional_flat_name)
        # If $optional_flat_name is None, $member_access is used.
        ("stream_id", None),
    ],

    # deps/quicly/include/quicly/loss.h
    "quicly_rtt_t": [
        ("minimum", None),
        ("smoothed", None),
        ("variance", None),
        ("latest",  None),
    ],

    # deps/quicly/lib/quicly.c
    "st_quicly_conn_t": [
        ("super.local.cid_set.plaintext.master_id", "master_id"),
    ],
}

# A block list to list useless or secret data fields
block_fields = {
    "quicly:crypto_decrypt": set(["decrypted"]),
    "quicly:crypto_update_secret": set(["secret"]),
    "quicly:crypto_send_key_update": set(["secret"]),
    "quicly:crypto_receive_key_update": set(["secret"]),
    "quicly:crypto_receive_key_update_prepare": set(["secret"]),

    "h2o:h3_packet_receive": set(["bytes"]),
}

# A block list for quicly-probes.d.
# USDT probes in quicly-probes.d are handled by default.
quicly_block_probes = set([
    "quicly:debug_message",
])

# An allow list for h2o-probes.d
# USDT probes in h2o-probes.d are not handled by default.
h2o_allow_probes = set([
    "h2o:h3s_accept",
    "h2o:h3s_destroy",
    "h2o:send_response_header",

    "h2o:h3_packet_receive",
    "h2o:h3_packet_forward",
])

h2o_probes_without_master_id = set([
    "h3s_accept",
    "h3_packet_receive",
    "h3_packet_forward",
])

# To rename field names for compatibility with:
# https://github.com/h2o/quicly/blob/master/quictrace-adapter.py
rename_map = {
    # common fields
    "at": "time",
    "master_id": "conn",

    # changed in the latest quicly master branch
    "num_bytes": "bytes_len",

    # quicly_rtt_t
    "minimum": "min-rtt",
    "smoothed": "smoothed-rtt",
    "variance": "variance-rtt",
    "latest": "latest-rtt",
}

st_quicly_conn_t_def = r"""
// This is enough for here. See `quicly.c` for the full definition.
struct st_quicly_conn_t {
  struct _st_quicly_conn_public_t super;
};
"""

re_flags = re.X | re.M | re.S
whitespace = r'(?:/\*.*?\*/|\s+)'
probe_decl = r'(?:\bprobe\s+(?:[a-zA-Z0-9_]+)\s*\([^\)]*\)\s*;)'
d_decl = r'(?:\bprovider\s*(?P<provider>[a-zA-Z0-9_]+)\s*\{(?P<probes>(?:%s|%s)*)\})' % (
    probe_decl, whitespace)

def strip_c_comments(s):
  return re.sub('//.*?\n|/\*.*?\*/', '', s, flags=re_flags)

def parse_d(context: dict, path: Path, allow_probes: set = None, block_probes: set = None):
  content = strip_c_comments(path.read_text())

  matched = re.search(d_decl, content, flags=re_flags)
  provider = matched.group('provider')

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
        st_name = strip_typename(arg_type)
        for st_field_access, st_field_name in struct_map.get(st_name, []):
          flat_args_map[st_field_name or st_field_access] = "typeof_%s__%s" % (st_name, st_field_name or st_field_access)
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
      st_name = strip_typename(arg_type)
      if st_name in struct_map:
        c += "  uint8_t %s[sizeof_%s] = {};\n" % (arg_name, st_name)
        c += "  bpf_usdt_readarg(%d, ctx, &buf);\n" % (i+1)
        c += "  bpf_probe_read(&%s, sizeof_%s, buf);\n" % (arg_name, st_name)
        for st_field_access, st_field_name in struct_map[st_name]:
          event_t_name = "%s.%s" % (probe_name, st_field_name or st_field_access)
          c += "  event.%s = get_%s__%s(%s);\n" % (
              event_t_name, st_name, st_field_name or st_field_access, arg_name)
      else:
        c += "  // (no fields in %s)\n" % (st_name)
    else:
      event_t_name = "%s.%s" % (probe_name, arg_name)
      c += "  bpf_usdt_readarg(%d, ctx, &event.%s);\n" % (i +
                                                          1, event_t_name)

  if fully_specified_probe_name == "h2o:h3s_accept":
    c += r"""
  h2o_to_quicly_conn.update(&event.h3s_accept.conn_id, &event.h3s_accept.master_id);
"""
  elif fully_specified_probe_name == "h2o:h3s_destroy":
    c += r"""
  const uint32_t *master_conn_id_ptr = h2o_to_quicly_conn.lookup(&event.h3s_destroy.conn_id);
  if (master_conn_id_ptr != NULL) {
    event.h3s_destroy.master_id = *master_conn_id_ptr;
  } else {
    bpf_trace_printk("h2o's conn_id=%lu is not associated to master_conn_id\n", event.h3s_destroy.conn_id);
  }
  h2o_to_quicly_conn.delete(&event.h3s_destroy.conn_id);
"""
  elif metadata["provider"] == "h2o" and probe_name not in h2o_probes_without_master_id:
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


def prepare_context(h2o_dir):
  context = {
      "id": 1,  # 1 is used for sched:sched_process_exit
      "probe_metadata": OrderedDict(),
      "h2o_dir": h2o_dir,
  }
  parse_d(context, h2o_dir.joinpath(quicly_probes_d),
          block_probes=quicly_block_probes)
  parse_d(context, h2o_dir.joinpath(h2o_probes_d),
          allow_probes=h2o_allow_probes)

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

DEFINE_RESOLVE_FUNC(int32_t);
DEFINE_RESOLVE_FUNC(uint32_t);
DEFINE_RESOLVE_FUNC(int64_t);
DEFINE_RESOLVE_FUNC(uint64_t);

static std::string gen_quic_bpf_header() {
  std::string bpf;
"""

  for st_name, st_fields in struct_map.items():
    # It limits a size of structs to 128
    # This is because the BPF stack has a limit to 512 bytes.
    generator += r"""
  bpf += "#define sizeof_%s " + std::to_string(std::min<size_t>(sizeof(struct %s), 128)) + "\n";
""" % (st_name, st_name)

    for st_field_access, st_field_name_alias in st_fields:
      name = "%s__%s" % (st_name, st_field_name_alias or st_field_access)
      generator += """  bpf += GEN_FIELD_INFO(struct %s, %s, "%s");\n""" % (st_name, st_field_access, name)

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

  event_t_decl = r"""
struct quic_event_t {
  uint8_t id;

  union {
"""

  for name, metadata in probe_metadata.items():
    fully_specified_probe_name = metadata["fully_specified_probe_name"]
    block_field_set = block_fields.get(fully_specified_probe_name, None)

    event_t_decl += "    struct { // %s\n" % fully_specified_probe_name
    for field_name, field_type in metadata["flat_args_map"].items():
      if block_field_set and field_name in block_field_set:
        continue

      if fully_specified_probe_name == "quicly:receive" and field_name == "bytes":
        f = "uint8_t %s[1]" % field_name  # for first-octet
      elif is_bin_type(field_type):
        f = "uint8_t %s[STR_LEN]" % field_name
      elif is_str_type(field_type):
        f = "char %s[STR_LEN]" % field_name
      else:
        f = "%s %s" % (field_type, field_name)

      event_t_decl += "      %s;\n" % f
    if metadata["provider"] == "h2o" and name not in h2o_probes_without_master_id:
      event_t_decl += "      typeof_st_quicly_conn_t__master_id master_id;\n"
    event_t_decl += "    } %s;\n" % name

  event_t_decl += r"""
    };
  };
  """

  bpf = r"""
#include <linux/sched.h>

#define STR_LEN 64
%s
BPF_PERF_OUTPUT(events);

// HTTP/3 tracing
BPF_HASH(h2o_to_quicly_conn, u64, u32);

// tracepoint sched:sched_process_exit
int trace_sched_process_exit(struct tracepoint__sched__sched_process_exit *ctx) {
  const struct task_struct *task = (const struct task_struct*)bpf_get_current_task();
  pid_t h2o_pid = task->tgid;
  pid_t h2o_tid = task->pid;
  if (!(h2o_pid == H2OLOG_H2O_PID && h2o_tid == H2OLOG_H2O_PID)) {
    return 0;
  }
  struct quic_event_t ev = { .id = 1 };
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}

""" % (event_t_decl)

  usdt_def = """
const std::vector<ebpf::USDT> &h2o_quic_tracer::init_usdt_probes(pid_t pid) {
  static const std::vector<ebpf::USDT> probes = {
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
void h2o_quic_tracer::do_handle_event(const void *data, int data_len) {
  const quic_event_t *event = static_cast<const quic_event_t*>(data);

  if (event->id == 1) { // sched:sched_process_exit
    exit(0);
  }

  // output JSON
  fprintf(out_, "{");

  switch (event->id) {
"""

  for probe_name in probe_metadata:
    metadata = probe_metadata[probe_name]
    fully_specified_probe_name = metadata["fully_specified_probe_name"]

    block_field_set = block_fields.get(fully_specified_probe_name, None)
    flat_args_map = metadata["flat_args_map"]

    handle_event_func += "  case %s: { // %s\n" % (
        metadata['id'], fully_specified_probe_name)
    handle_event_func += '    json_write_pair_n(out_, STR_LIT("type"), "%s");\n' % probe_name.replace("_", "-")
    handle_event_func += '    json_write_pair_c(out_, STR_LIT("seq"), seq_);\n'

    for field_name, field_type in flat_args_map.items():
      if block_field_set and field_name in block_field_set:
        continue
      json_field_name = rename_map.get(field_name, field_name).replace("_", "-")
      event_t_name = "%s.%s" % (probe_name, field_name)
      if fully_specified_probe_name == "quicly:receive" and field_name == "bytes":
        handle_event_func += '    json_write_pair_c(out_, STR_LIT("first-octet"), event->receive.bytes[0]);\n'
      elif not is_bin_type(field_type):
        handle_event_func += '    json_write_pair_c(out_, STR_LIT("%s"), event->%s);\n' % (
            json_field_name, event_t_name)
      else:  # bin type (it should have the correspinding length arg)
        len_names = set([field_name + "_len", "len", "num_" + field_name])

        for n in flat_args_map:
          if n in len_names:
            len_event_t_name = "%s.%s" % (probe_name, n)

        # A string might be truncated in STRLEN
        handle_event_func += '    json_write_pair_c(out_, STR_LIT("%s"), event->%s, (event->%s < STR_LEN ? event->%s : STR_LEN));\n' % (
            json_field_name, event_t_name, len_event_t_name, len_event_t_name)

    if metadata["provider"] == "h2o":
      if probe_name not in h2o_probes_without_master_id:
        handle_event_func += '    json_write_pair_c(out_, STR_LIT("conn"), event->%s.master_id);\n' % (
            probe_name)
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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <string>
#include <algorithm>

#include "quicly.h"

#include "h2olog.h"
#include "json.h"

#define STR_LEN 64
#define STR_LIT(s) s, strlen(s)

class h2o_quic_tracer : public h2o_tracer {
protected:
  virtual void do_handle_event(const void *data, int len);
  virtual void do_handle_lost(uint64_t lost);
public:
  virtual const std::vector<ebpf::USDT> &init_usdt_probes(pid_t h2o_pid);
  virtual std::string bpf_text();
};

%s
%s
%s
%s
%s

void h2o_quic_tracer::do_handle_lost(uint64_t lost)
{
  fprintf(out_,
          "{"
          "\"type\":\"h2olog-event-lost\","
          "\"seq\":%%" PRIu64 ","
          "\"time\":%%" PRIu64 ","
          "\"lost\":%%" PRIu64 "}\n",
          seq_, time_milliseconds(), lost);
}

std::string h2o_quic_tracer::bpf_text() {
  return gen_quic_bpf_header() + R"(
%s
)";
}

h2o_tracer *create_quic_tracer() {
  return new h2o_quic_tracer;
}

""" % (build_typedef_for_cplusplus(), build_bpf_header_generator(), event_t_decl, usdt_def, handle_event_func, bpf))


def main():
  try:
    (_, h2o_dir, output_file) = sys.argv
  except:
    print("usage: %s h2o_dir output_file" % sys.argv[0])
    sys.exit(1)

  context = prepare_context(Path(h2o_dir))
  generate_cplusplus(context, output_file)


if __name__ == "__main__":
  main()
