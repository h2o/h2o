"""
Extracts documentation from cifra headers.

We want to embed documentation in headers for good
locality.  But want to write rst for formatting by sphinx.
This is a problem.

'Breathe' provides a bridge between doxygen and sphinx,
but doxygen's documentation markup is pretty awful.

Therefore, we write rst directly in C headers, and then
extract it here.  The rules are: a C block comment
starting exactly '/* .. ' is dedented, and then included
verbatim.  The convention is that the documentation
preceeds the C declarations they apply to, and that struct
members are documented before the struct they are contained
within. eg:

/* .. c:function:: int foo(int bar)
 * Foos a bar, returning the foo coefficient.
 */
int foo(int bar);

/* .. c:type:: thing
 * Container for things.
 *
 * .. c:member:: int thing.foo
 * Count of foos.
 * 
 * .. c:member:: int thing.bar
 * Count of bars.
 */
typedef struct
{
  int foo;
  int bar;
} thing;

As a special effect, the following tokens are replaced
in the comments:

 - $DECL: the immediately following function declaration
"""

import glob
import re
import StringIO

# We know which headers constitute the external interface.
EXTERNAL = """
aes
cf_config
chash
hmac
modes
pbkdf2
prp
salsa20
sha1
sha2
sha3
norx
poly1305
chacha20poly1305
drbg
""".split()

# Basic idea of a C identifier
C_IDENTIFIER = '[a-zA-Z_][a-zA-Z0-9_]+'

DECL_RE = re.compile(r'^\s*(.+?' + C_IDENTIFIER + '\(.+?\));', re.MULTILINE | re.DOTALL)
COMMENT_RE = re.compile(r'^\s*\/\* (\.\..*?) \*\/$', re.MULTILINE | re.DOTALL)
INTRO_RE = re.compile(r'^\s*\/\*\*(.*?)\*\/$', re.MULTILINE | re.DOTALL)
NEW_SECTION_RE = re.compile(r'^..+\n(==+|--+)$', re.MULTILINE)

class section(object):
    def __init__(self):
        self.intro = []
        self.macros = []
        self.types = []
        self.functions = []
        self.values = []

    def __repr__(self):
        return repr(self.format()[:30])
    
    def __str__(self):
        return repr(self.format()[:30])

    def format(self):
        f = StringIO.StringIO()

        def emit(title, section):
            if len(section) == 0:
                return
           
            if title:
                print >>f, title
                print >>f, '*' * len(title)
                print >>f

            for s in section:
                print >>f, s.getvalue()
        
        emit(None, self.intro)
        emit('Macros', self.macros)
        emit('Types', self.types)
        emit('Functions', self.functions)
        emit('Values', self.values)

        return f.getvalue()

    def is_empty(self):
        items = len(self.intro) + len(self.macros) + len(self.types) + \
                len(self.functions) + len(self.values)
        return 0 == items
    
    def add_item(self, sec):
        f = StringIO.StringIO()
        sec.append(f)
        return f

def massage_decl(decl):
    """
    Tart-up a C function declaration: remove storage qualifiers,
    smush onto one line, escape asterisks.
    """
    for storage in 'extern static inline'.split():
        decl = decl.replace(storage + ' ', '')
    
    fixed_lines = ' '.join(line.strip() for line in decl.splitlines())

    return fixed_lines.replace('*', '\\*')

def replace_decl(comment, comment_match, header):
    if '$DECL' not in comment:
        return comment

    start = comment_match.end(0) + 1
    decl_match = DECL_RE.match(header, start)

    if decl_match is None:
        print 'Cause:', comment
        print 'Trailer:', header[start:start+60]
        raise IOError('$DECL present but cannot find following DECL')

    decl = decl_match.group(1)
    decl = massage_decl(decl)
    return comment.replace('$DECL', decl)

def decomment(lines):
    for i in range(len(lines)):
        if lines[i].startswith(' *'):
            lines[i] = lines[i][3:]
        lines[i] = lines[i].strip()

def drop_empty_prefix(lines):
    while len(lines) and lines[0] == '':
        lines.pop(0)

def starts_new_section(lines):
    txt = '\n'.join(lines)
    r = NEW_SECTION_RE.search(txt) is not None
    return r

def process(header, rst):
    """
    Converts a header into restructured text.

    header is a file-like opened to read the header.
    rst is a file-like opened to write the rst results.
    """

    hh = header.read()

    # Collect definitions into sections
    sec = None
    all_sections = []
    intro, macros, types, functions, values = [], [], [], [], []

    def add_section():
        if sec and not sec.is_empty():
            all_sections.append(sec)
        return section()

    sec = add_section()

    offs = 0

    while True:
        intro_match = INTRO_RE.search(hh, offs)
        comment_match = COMMENT_RE.search(hh, offs)

        if intro_match is None and comment_match is None:
            break

        # process earliest occuring
        if intro_match is not None and (comment_match is None or intro_match.start(0) < comment_match.start(0)):
            txt = intro_match.group(1)
            
            lines = txt.splitlines()
            decomment(lines)
            drop_empty_prefix(lines)

            if starts_new_section(lines):
                sec = add_section()

            outf = sec.add_item(sec.intro)

            for l in lines:
                print >>outf, l
            offs = intro_match.end(0) + 1
            continue

        if comment_match is not None and (intro_match is None or comment_match.start(0) < intro_match.start(0)):
            txt = comment_match.group(1)

            # work out which section this goes into
            outf = None
            if '.. c:macro::' in txt:
                outf = sec.add_item(sec.macros)
            elif '.. c:type::' in txt:
                outf = sec.add_item(sec.types)
            elif '.. c:var::' in txt:
                outf = sec.add_item(sec.values)
            elif '.. c:function::' in txt:
                outf = sec.add_item(sec.functions)
            elif '.. c:member::' in txt:
                if len(types) == 0:
                    raise IOError('c:member must come after a c:type')
                outf = types[-1]
            else:
                raise IOError('Cannot categorise item: ' + txt)

            # expand $DECL
            txt = replace_decl(txt, comment_match, hh)
            
            # decomment lines
            lines = txt.splitlines()
            decomment(lines)

            # domain lines are unindented
            while lines and lines[0].startswith('.. '):
                print >>outf, lines.pop(0)
            print >>outf

            # empty prefix lines are stripped
            drop_empty_prefix(lines)

            # other lines are indented
            for line in lines:
                if len(line):
                    line = '  ' + line
                print >>outf, line
            
            offs = comment_match.end(0) + 1
            continue

    add_section()

    for sec in all_sections:
        rst.write(sec.format())

def run():
    for fn in EXTERNAL:
        print '** build', fn
        header = '../src/' + fn + '.h'
        rst = fn + '.rst'
        with open(header, 'r') as fh:
            with open(rst, 'w') as fr:
                process(fh, fr)

if __name__ == '__main__':
    run()
