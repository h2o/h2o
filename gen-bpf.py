#!/usr/bin/env python3
# usage: gen-bpf.py d_files_dir output_file

from __future__ import print_function
import re, ctypes, sys, json, binascii, os, time
from pprint import pprint
from collections import OrderedDict

try:
    (_prog, d_files_dir, output_file) = sys.argv
except:
    print("usage: %s h2o_path d_files_dir output_file" % sys.argv[0])
    sys.exit(1)

block_fields = {
    "quicly:crypto_decrypt": set(["decrypted"]),
    "quicly:receive": set(["bytes"]),
    "quicly:crypto_update_secret": set(["secret"]),
    "quicly:crypto_send_key_update": set(["secret"]),
    "quicly:crypto_receive_key_update": set(["secret"]),
    "quicly:crypto_receive_key_update_prepare": set(["secret"]),
}

block_probes = set([
    "quicly:debug_message",
])

# mapping from proves.d's to quic-trace's:
rename_map = {
    "at": "time",
    "master_id": "master_conn_id",
}

def read_from_file(path):
    with open(path, "r") as f:
        return f.read()

def write_to_file(path, content):
    with open(path, "w") as f:
        f.write(content)

d = read_from_file(os.path.join(d_files_dir, "quicly-probes.d"))

whitespace = r'(?:/\*.*?\*/|\s+)'
probe_decl = r'(?:\bprobe\s+(?:[a-zA-Z0-9_]+)\s*\([^\)]*\)\s*;)'
d_decl = r'(?:\bprovider\s*(?P<provider>[a-zA-Z0-9_]+)\s*\{(?P<probes>(?:%s|%s)*)\})' % (probe_decl, whitespace)

re_flags = re.X | re.M | re.S

matched = re.search(d_decl, d, flags = re_flags)
provider = matched.group('provider')

struct_decl = read_from_file(os.path.join(os.path.dirname(__file__), "data-types.h"))

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

def build_tracer(metadata):
    c = r"""
int %s(struct pt_regs *ctx) {
    void *buf = NULL;
    struct event_t event = { .id = %d };

""" % (build_tracer_name(metadata), metadata['id'])

    block_field_set = block_fields.get(metadata["fully_specified_probe_name"], set())

    i = 0
    args = metadata['args']
    str_i = 0
    int_i = 0
    while i < len(args):
        arg = args[i]
        arg_name = arg['name']
        arg_type = arg['type']
        c += "    // %s %s\n" % (arg_type, arg_name)
        if arg_name in block_field_set:
            c += "    // (ignored because it's in the block list)\n"
            i += 1
            continue

        if is_str_type(arg_type):
            c += "    bpf_usdt_readarg(%d, ctx, &buf);\n" % (i+1)
            # Use `sizeof(buf)` instead of a length variable, because older kernels
            # do not accept a variable for `bpf_probe_read()`'s length parameter.
            c += "    bpf_probe_read(&event.s%d, sizeof(event.s%d), buf);\n" % (str_i, str_i)
            str_i += 1
        elif is_ptr_type(arg_type):
            c += "    %s %s = {};\n" % (arg_type.replace("*", ""), arg_name)
            c += "    bpf_usdt_readarg(%d, ctx, &buf);\n" % (i+1)
            c += "    bpf_probe_read(&%s, sizeof(%s), buf);\n" % (arg_name, arg_name)
            st_name = strip_typename(arg_type)
            for st_key, st_valtype in st_map[st_name].items():
                c += "    event.i%d = %s.%s; /* %s */\n" % (int_i, arg_name, st_key, st_valtype)
                int_i += 1
        else:
            c += "    bpf_usdt_readarg(%d, ctx, &event.i%d);\n" % (i+1, int_i)
            int_i += 1
        i += 1
    diff = ""
    if str_i > 0:
        diff = " - %d" % (str_i * 32)
    c += """
    if (events.perf_submit(ctx, &event, sizeof(event)%s) != 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}\n""" % diff
    return c


st_map = {}
for (st_name, content) in re.findall(r'struct\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}', struct_decl, flags = re_flags):
    st = st_map[st_name] = {}
    for (ctype, name, is_array) in re.findall(r'(\w+[^;]*[\w\*])\s+([a-zA-Z0-9_]+)(\[\d+\])?;', content, flags = re_flags):
        if "dummy" in name:
            continue
        st[name] = ctype + is_array

probe_metadata = OrderedDict()
probe_id2metadata = OrderedDict()
max_ints = 0
max_strs = 0

id = 0
for (name, args) in re.findall(r'\bprobe\s+([a-zA-Z0-9_]+)\(([^\)]+)\);', matched.group('probes'), flags = re_flags):
    arg_list = re.split(r'\s*,\s*', args, flags = re_flags)
    id += 1
    metadata = {
        "id": id,
        "provider": provider,
        "name": name,
        "fully_specified_probe_name": "%s:%s" % (provider, name),
    }
    probe_id2metadata[id] = metadata
    probe_metadata[name] = metadata
    args = metadata['args'] = list(map(
        lambda arg: re.match(r'(?P<type>\w[^;]*[^;\s])\s*\b(?P<name>[a-zA-Z0-9_]+)', arg, flags = re_flags).groupdict(),
        arg_list))

    # args map is a flat arg list
    args_map = metadata['args_map'] = OrderedDict()

    n_ints = 0
    n_strs = 0
    for arg in args:
        if is_str_type(arg['type']):
            args_map["s%d" % n_strs] = (arg['name'], arg['type'])
            n_strs += 1
        elif is_ptr_type(arg['type']):
            # it assumes that all the fields in the struct are values (i.e. integers)
            for st_key, st_valtype in st_map[strip_typename(arg['type'])].items():
                args_map["i%d" % n_ints] = (st_key, st_valtype)
                n_ints += 1
        else:
            args_map["i%d" % n_ints] = (arg['name'], arg['type'])
            n_ints += 1

    if max_ints < n_ints:
        max_ints = n_ints
    if max_strs < n_strs:
        max_strs = n_strs

event_t_decl = r"""
struct event_t {
    uint8_t id;

"""

for i in range(max_ints):
    event_t_decl += "    uint64_t i%d;\n" % i
for i in range(max_strs):
    event_t_decl += "    char s%d[32];\n" % i

event_t_decl += r"""
};
"""

bpf = event_t_decl + r"""

BPF_PERF_OUTPUT(events);

"""

usdt_def = """
static
std::vector<ebpf::USDT> quic_init_usdt_probes(pid_t pid) {
  const std::vector<ebpf::USDT> probes = {
"""

for metadata in probe_metadata.values():
    if metadata["fully_specified_probe_name"] in block_probes:
        continue

    bpf += build_tracer(metadata)
    usdt_def += """      ebpf::USDT(pid, "%s", "%s", "%s"),\n""" % (metadata['provider'], metadata['name'], build_tracer_name(metadata))

usdt_def += """
    };
    return probes;
}
"""

handle_event_func = r"""

static
void quic_handle_event(void *context, void *data, int data_len) {
    h2o_tracer_t *tracer = static_cast<h2o_tracer_t*>(context);
    tracer->count++;

    FILE *out = tracer->out;

    const event_t *event = static_cast<const event_t*>(data);

    // output JSON
    fprintf(out, "{");

    switch (event->id) {
"""

for probe_name in probe_metadata:
    metadata = probe_metadata[probe_name]
    block_field_set = block_fields.get(metadata["fully_specified_probe_name"], None)
    args_map = metadata["args_map"]

    handle_event_func += "    case %s: { // %s\n" % (metadata['id'], probe_name)
    handle_event_func += '        json_write_pair(out, false, "type", "%s");\n' % probe_name

    for event_t_name, (probe_field_name, arg_type) in args_map.items():
        if block_field_set and probe_field_name in block_field_set:
            continue
        data_field_name = rename_map.get(probe_field_name, probe_field_name)
        if not is_bin_type(arg_type):
            handle_event_func += '        json_write_pair(out, true, "%s", (%s)(event->%s));\n' % (data_field_name, arg_type, event_t_name)
        else:
            len_name = probe_field_name + "_len"
            for e, (n, t) in args_map.items():
                if n == len_name or n == "len":
                    (len_event_t_name, len_arg_type) = (e, t)
            handle_event_func += '        json_write_pair(out, true, "%s", (%s)(event->%s), (%s)(event->%s));\n' % (data_field_name, arg_type, event_t_name, len_arg_type, len_event_t_name)

    handle_event_func += "        break;\n"
    handle_event_func += "    }\n"

handle_event_func += r"""
    default:
        std::abort();
    }

    fprintf(out, "}\n");
"""
handle_event_func += "}\n";

write_to_file(output_file, r"""
// Generated code. Do not edit it here!

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "h2olog.h"
#include "data-types.h"
#include "json.h"

// BPF modules written in C
const char *pbf_text = R"(
#include "data-types.h"

%s
)";
%s
%s
%s

static
const char *quic_bpf_ext() {
    return pbf_text;
}

h2o_tracer_t *create_quic_tracer(void) {
  h2o_tracer_t *tracer = new h2o_tracer_t();
  tracer->handle_event = quic_handle_event;
  tracer->init_usdt_probes = quic_init_usdt_probes;
  tracer->bpf_text = quic_bpf_ext;
  tracer->count = 0;
  tracer->out = nullptr;
  return tracer;
}

""" % (bpf, usdt_def, event_t_decl, handle_event_func))

