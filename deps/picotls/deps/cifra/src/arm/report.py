"""
Interprets logs from test runs.  Outputs ASCII
tables containing results, json data, etc.
"""

import json
import sys

archs = 'stm32f0 stm32f1 stm32f3'.split()
tests = """
aes128block_test
aes256block_test
aes128sched_test
aes256sched_test
hashtest_sha256
hashtest_sha512
hashtest_sha3_256
hashtest_sha3_512
aes128gcm_test
aes128eax_test
aes128ccm_test
norx_test
salsa20_test
chacha20_test
poly1305_test
hmacsha256_test
curve25519_test
aeadperf_norx
aeadperf_aes128gcm
aeadperf_aes128eax
aeadperf_aes128ccm
aeadperf_aes256gcm
aeadperf_aes256eax
aeadperf_aes256ccm
aeadperf_chacha20poly1305
do_nothing
""".split()

arch_names = dict(
        stm32f0 = 'Cortex-M0',
        stm32f1 = 'Cortex-M3',
        stm32f3 = 'Cortex-M4F'
        )

base_test = 'do_nothing'

def extract(arch, test):
    fn = 'run.%s.%s.log' % (test, arch)

    code_size = 0
    data_size = 0
    cycle_count = None
    stack_usage = None
    brackets = None
    current_bracket = None

    try:
        lines = open(fn).readlines()
    except IOError:
        return None

    for l in lines:
        if 'LOAD' in l:
            parts = l.split()
            assert len(parts) >= 8
            assert 'LOAD' == parts[0]
            if parts[6] == 'RWE':
                code_size += long(parts[5], 16)
            if parts[6] == 'RW':
                data_size += long(parts[5], 16)

        if l.startswith('bracket = '):
            bracket = long(l.split(' = ')[1].strip(), 16)
            current_bracket = bracket
            if brackets is None:
                brackets = {}
            brackets[current_bracket] = dict()

        if l.startswith('cycles = '):
            cycle_count = long(l.split(' = ')[1].strip(), 16)
            if current_bracket is not None:
                brackets[current_bracket]['cycle_count'] = cycle_count

        if l.startswith('stack = '):
            stack_usage = long(l.split(' = ')[1].strip(), 16)
            if current_bracket is not None:
                brackets[current_bracket]['stack_usage'] = stack_usage

    return dict(
            code_size = code_size,
            data_size = data_size,
            cycle_count = cycle_count,
            stack_usage = stack_usage,
            brackets = brackets
            )

def print_table(rows):
    header, rows = rows[0], rows[1:]
    assert not [True for r in rows if len(r) != len(header)]
    widths = []
    for i, h in enumerate(header):
        widths.append(max([len(h)] + [len(r[i]) for r in rows]))

    def print_row(row):
        print ' | '.join(c + (' ' * (widths[i] - len(c))) for i, c in enumerate(row))
    
    print_row(header)
    print_row(['-' * w for w in widths])
    for r in rows:
        print_row(r)

results = {}

for arch in archs:
    for test in tests:
        inf = extract(arch, test)
        if inf:
            results.setdefault(arch, {})[test] = inf

for arch in results.keys():
    if base_test not in results[arch]:
        print 'need', base_test, 'results to report for', arch
        continue

    base_result = results[arch][base_test]

    for test in results[arch].keys():
        if test == base_test:
            continue

        results[arch][test]['code_size'] -= base_result['code_size']

def tabulate_aes(arch, block_result, sched_result, table = None):
    if table is None:
        table = []
        table.append((
            'Core',
            'Cycles (key schedule + block)',
            'Cycles (key schedule)',
            'Cycles (block)',
            'Stack',
            'Code size'
            ))

    table.append(
            (
                arch_names[arch],
                '%d' % block_result['cycle_count'],
                '%d' % sched_result['cycle_count'],
                '%d' % (block_result['cycle_count'] - sched_result['cycle_count']),
                '%dB' % block_result['stack_usage'],
                '%dB' % block_result['code_size']
            ))

    return table

def print_std(result):
    print """* **Cycles**: %(cycle_count)d
* **Stack**: %(stack_usage)dB
* **Code size**: %(code_size)dB
""" % result

def tabulate_std(arch, result, table = None):
    if table is None:
        table = []
        table.append(('Core', 'Cycles', 'Stack', 'Code size'))

    table.append(
            (
                arch_names[arch],
                '%d' % result['cycle_count'],
                '%dB' % result['stack_usage'],
                '%dB' % result['code_size']
            ))

    return table

def tabulate(mktab):
    table = None
    for arch in archs:
        if arch not in results:
            continue
        table = mktab(arch, table)
    print_table(table)

def convert_brackets(metric, tests):
    for arch in archs:
        arch_result = {}

        # collect results for each test
        for t in tests:
            if arch not in results or t not in results[arch]:
                print 'missing', arch, t
                continue
            data = results[arch][t]['brackets']
            arch_result[t] = [[b, data[b][metric]] for b in sorted(data.keys())]

        # convert into list of [bracket, test-1, test-2, ...] lists
        out = []
        if len(arch_result) == 0:
            continue
        first_row = arch_result.values()[0]

        for i in range(len(first_row)):
            row = [ first_row[i][0] ]

            for k in sorted(arch_result.keys()):
                if len(arch_result[k]) != len(first_row):
                    print 'warn:', 'test', k, 'did not complete?'
                rr = arch_result[k][i]
                row.append(rr[1])

            out.append(row)

        print json.dumps(out)

convert_brackets('cycle_count',
        [
            'aeadperf_norx',
            'aeadperf_aes128gcm',
            'aeadperf_aes128eax',
            'aeadperf_aes128ccm',
            'aeadperf_aes256gcm',
            'aeadperf_aes256eax',
            'aeadperf_aes256ccm',
            'aeadperf_chacha20poly1305'
        ])
convert_brackets('stack_usage',
        [
            'aeadperf_norx',
            'aeadperf_aes128gcm',
            'aeadperf_aes128eax',
            'aeadperf_aes128ccm',
            'aeadperf_aes256gcm',
            'aeadperf_aes256eax',
            'aeadperf_aes256ccm',
            'aeadperf_chacha20poly1305'
        ])

# screwed if we need other block ciphers
print '###', '128-bit key'
tabulate(lambda arch, table: tabulate_aes(arch, results[arch]['aes128block_test'], results[arch]['aes128sched_test'], table))
print

print '###', '256-bit key'
tabulate(lambda arch, table: tabulate_aes(arch, results[arch]['aes256block_test'], results[arch]['aes256sched_test'], table))
print

def do_table(title, test):
    print '##', title
    tabulate(lambda arch, table: tabulate_std(arch, results[arch][test], table))
    print

do_table('AES128-GCM', 'aes128gcm_test')
do_table('AES128-EAX', 'aes128eax_test')
do_table('AES128-CCM', 'aes128ccm_test')
do_table('NORX32', 'norx_test')
do_table('ChaCha20', 'chacha20_test')
do_table('Salsa20', 'salsa20_test')
do_table('SHA256', 'hashtest_sha256')
do_table('SHA512', 'hashtest_sha512')
do_table('SHA3-256', 'hashtest_sha3_256')
do_table('SHA3-512', 'hashtest_sha3_512')
do_table('HMAC-SHA256', 'hmacsha256_test')
do_table('Poly1305-AES', 'poly1305_test')
do_table('Curve25519', 'curve25519_test')

if '--aead' in sys.argv:
    do_table('AEAD-Shootout: NORX', 'aeadperf_norx')
    do_table('AEAD-Shootout: AES-128-GCM', 'aeadperf_aes128gcm')
    do_table('AEAD-Shootout: AES-128-EAX', 'aeadperf_aes128eax')
    do_table('AEAD-Shootout: AES-128-CCM', 'aeadperf_aes128ccm')
    do_table('AEAD-Shootout: AES-256-GCM', 'aeadperf_aes256gcm')
    do_table('AEAD-Shootout: AES-256-EAX', 'aeadperf_aes256eax')
    do_table('AEAD-Shootout: AES-256-CCM', 'aeadperf_aes256ccm')
    do_table('AEAD-Shootout: ChaCha20-Poly1305', 'aeadperf_chacha20poly1305')
