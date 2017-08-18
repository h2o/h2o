#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals
import ctypes
import onigmo
import sys
import io
import locale

nerror = 0
nsucc = 0
nfail = 0

# default encoding
onig_encoding = onigmo.ONIG_ENCODING_EUC_JP

# special syntactic settings
syntax_default = ctypes.byref(onigmo.OnigSyntaxType())
onigmo.onig_copy_syntax(syntax_default, onigmo.ONIG_SYNTAX_DEFAULT)
onigmo.onig_set_syntax_options(syntax_default,
        onigmo.onig_get_syntax_options(syntax_default)
            & ~onigmo.ONIG_OPTION_ASCII_RANGE)


def get_encoding_name(onigenc):
    """Return the name of specified onigmo.OnigEncoding.

    arguments:
      enc -- an instance of onigmo.OnigEncoding
    """
    name = onigenc[0].name.decode()
    encnamemap = {"Windows-31J": "CP932",
            "ASCII-8BIT": "ASCII"}
    if name in encnamemap:
        name = encnamemap[name]
    return name

def is_unicode_encoding(enc):
    """Check if the encoding is Unicode encoding.

    arguments:
      enc -- encoding name or an instance of onigmo.OnigEncoding
    """
    return enc in (onigmo.ONIG_ENCODING_UTF32_LE,
                   onigmo.ONIG_ENCODING_UTF32_BE,
                   onigmo.ONIG_ENCODING_UTF16_LE,
                   onigmo.ONIG_ENCODING_UTF16_BE,
                   onigmo.ONIG_ENCODING_UTF8,
                   'UTF-16LE', 'UTF-16BE', 'UTF-32LE', 'UTF-32BE', 'UTF-8')

def is_ascii_incompatible_encoding(enc):
    """Check if the encoding is ASCII-incompatible encoding.

    arguments:
      enc -- encoding name or an instance of onigmo.OnigEncoding
    """
    return enc in (onigmo.ONIG_ENCODING_UTF32_LE,
                   onigmo.ONIG_ENCODING_UTF32_BE,
                   onigmo.ONIG_ENCODING_UTF16_LE,
                   onigmo.ONIG_ENCODING_UTF16_BE,
                   'UTF-16LE', 'UTF-16BE', 'UTF-32LE', 'UTF-32BE')


class strptr:
    """a helper class to get a pointer to a string"""
    def __init__(self, s):
        if not isinstance(s, bytes):
            raise TypeError
        self._str = s
        try:
            # CPython 2.x/3.x
            self._ptr = ctypes.cast(self._str, ctypes.c_void_p)
        except TypeError:
            # PyPy 1.x
            self._ptr = ctypes.c_void_p(self._str)

    def getptr(self, offset=0):
        if offset == -1:    # -1 means the end of the string
            offset = len(self._str)
        elif offset > len(self._str):
            raise IndexError
        return self._ptr.value + offset

def cc_to_cb(s, enc, cc):
    """convert char count to byte count

    arguments:
      s -- unicode string
      enc -- encoding name
      cc -- char count
    """
    if cc == -1:
        return -1
    s = s.encode('UTF-32LE')
    clen = cc * 4
    if clen > len(s):
        raise IndexError
    return len(s[:clen].decode('UTF-32LE').encode(enc))

def print_result(result, pattern, file=None):
    if not file:
        file = sys.stdout
    print(result + ": ", end='', file=file)
    try:
        print(pattern, file=file)
    except UnicodeEncodeError as e:
        print('(' + str(e) + ')')

def decode_errmsg(msg):
    encoding = get_encoding_name(onig_encoding)
    if is_ascii_incompatible_encoding(encoding):
        encoding = 'ASCII'
    return msg.value.decode(encoding, 'replace')


class SearchType:
    FORWARD = 0
    BACKWARD = 1
    MATCH = 2

def xx(pattern, target, s_from, s_to, mem, not_match,
        searchtype=SearchType.FORWARD,
        gpos=-1, startpos=0, endpos=-1,
        syn=syntax_default, opt=onigmo.ONIG_OPTION_DEFAULT,
        err=onigmo.ONIG_NORMAL, execerr=onigmo.ONIG_NORMAL):
    global nerror
    global nsucc
    global nfail

    encoding = get_encoding_name(onig_encoding)

    reg = onigmo.OnigRegex()
    einfo = onigmo.OnigErrorInfo()
    msg = ctypes.create_string_buffer(onigmo.ONIG_MAX_ERROR_MESSAGE_LEN)

    pattern2 = pattern
    if not isinstance(pattern, bytes):
        pattern2 = pattern.encode(encoding)
    patternp = strptr(pattern2)

    target2 = target
    if not isinstance(target, bytes):
        s_from = cc_to_cb(target, encoding, s_from)
        s_to = cc_to_cb(target, encoding, s_to)
        gpos = cc_to_cb(target, encoding, gpos)
        startpos = cc_to_cb(target, encoding, startpos)
        endpos = cc_to_cb(target, encoding, endpos)
        target2 = target.encode(encoding)
    targetp = strptr(target2)

    # cut very long outputs (used for showing message)
    pattern = pattern2.decode(encoding, 'replace')
    target = target2.decode(encoding, 'replace')
    limit = 100
    if len(pattern) > limit:
        pattern = pattern[:limit] + "..."
    if len(target) > limit:
        target = target[:limit] + "..."

    # Compile
    r = onigmo.onig_new(ctypes.byref(reg),
            patternp.getptr(), patternp.getptr(-1),
            opt, onig_encoding, syn, ctypes.byref(einfo));
    if r != 0:
        # Error
        onigmo.onig_error_code_to_str(msg, r, ctypes.byref(einfo))
        if r == err:
            nsucc += 1
            print_result("OK(E)", "%s (/%s/ '%s')" % \
                    (decode_errmsg(msg), pattern, target))
        else:
            nerror += 1
            print_result("ERROR", "%s (/%s/ '%s')" % \
                    (decode_errmsg(msg), pattern, target), file=sys.stderr)
        return

    if err != onigmo.ONIG_NORMAL:
        nfail += 1
        print_result("FAIL(E)", "/%s/ '%s'" % (pattern, target))
        onigmo.onig_free(reg)
        return

    # Execute
    region = onigmo.onig_region_new()
    if searchtype == SearchType.FORWARD:
        if gpos >= 0:
            r = onigmo.onig_search_gpos(reg,
                        targetp.getptr(), targetp.getptr(-1),
                        targetp.getptr(gpos),
                        targetp.getptr(startpos), targetp.getptr(endpos),
                        region, onigmo.ONIG_OPTION_NONE);
        else:
            r = onigmo.onig_search(reg,
                        targetp.getptr(), targetp.getptr(-1),
                        targetp.getptr(startpos), targetp.getptr(endpos),
                        region, onigmo.ONIG_OPTION_NONE);
    elif searchtype == SearchType.BACKWARD:
        if gpos >= 0:
            r = onigmo.onig_search_gpos(reg,
                        targetp.getptr(), targetp.getptr(-1),
                        targetp.getptr(gpos),
                        targetp.getptr(endpos), targetp.getptr(startpos),
                        region, onigmo.ONIG_OPTION_NONE);
        else:
            r = onigmo.onig_search(reg,
                        targetp.getptr(), targetp.getptr(-1),
                        targetp.getptr(endpos), targetp.getptr(startpos),
                        region, onigmo.ONIG_OPTION_NONE);
    elif searchtype == SearchType.MATCH:
        r = onigmo.onig_match(reg, targetp.getptr(), targetp.getptr(-1),
                        targetp.getptr(startpos),
                        region, onigmo.ONIG_OPTION_NONE);
    else:
        nerror += 1
        print_result("ERROR", "wrong searchtype", file=sys.stderr)
        onigmo.onig_free(reg)
        onigmo.onig_region_free(region, 1)
        return

    if r < onigmo.ONIG_MISMATCH:
        # Error
        onigmo.onig_error_code_to_str(msg, r)
        if r == execerr:
            nsucc += 1
            print_result("OK(E)", "%s (/%s/ '%s')" % \
                    (decode_errmsg(msg), pattern, target))
        else:
            nerror += 1
            print_result("ERROR", "%s (/%s/ '%s')" % \
                    (decode_errmsg(msg), pattern, target), file=sys.stderr)
        onigmo.onig_free(reg)
        onigmo.onig_region_free(region, 1)
        return

    if r == onigmo.ONIG_MISMATCH:
        # Not matched
        if not_match:
            nsucc += 1
            print_result("OK(N)", "/%s/ '%s'" % (pattern, target))
        else:
            nfail += 1
            print_result("FAIL", "/%s/ '%s'" % (pattern, target))
    else:
        # Matched
        if not_match:
            nfail += 1
            print_result("FAIL(N)", "/%s/ '%s'" % (pattern, target))
        else:
            start = region[0].beg[mem]
            end = region[0].end[mem]
            if (start == s_from) and (end == s_to):
                nsucc += 1
                print_result("OK", "/%s/ '%s'" % (pattern, target))
            else:
                nfail += 1
                print_result("FAIL", "/%s/ '%s' %d-%d : %d-%d" % (pattern, target,
                        s_from, s_to, start, end))
    onigmo.onig_free(reg)
    onigmo.onig_region_free(region, 1)

def x2(pattern, target, s_from, s_to, **kwargs):
    xx(pattern, target, s_from, s_to, 0, False, **kwargs)

def x3(pattern, target, s_from, s_to, mem, **kwargs):
    xx(pattern, target, s_from, s_to, mem, False, **kwargs)

def n(pattern, target, **kwargs):
    xx(pattern, target, 0, 0, 0, True, **kwargs)


def set_encoding(enc):
    """Set the encoding used for testing.

    arguments:
      enc -- encoding name or an instance of onigmo.OnigEncoding
    """
    global onig_encoding

    if enc == None:
        return
    if isinstance(enc, onigmo.OnigEncoding):
        onig_encoding = enc
    else:
        encs = {"EUC-JP": onigmo.ONIG_ENCODING_EUC_JP,
                "SJIS": onigmo.ONIG_ENCODING_SJIS,
                "CP932": onigmo.ONIG_ENCODING_CP932,
                "UTF-8": onigmo.ONIG_ENCODING_UTF8,
                "UTF-16LE": onigmo.ONIG_ENCODING_UTF16_LE,
                "UTF-16BE": onigmo.ONIG_ENCODING_UTF16_BE,
                "UTF-32LE": onigmo.ONIG_ENCODING_UTF32_LE,
                "UTF-32BE": onigmo.ONIG_ENCODING_UTF32_BE}
        onig_encoding = encs[enc.upper()]

def get_encoding():
    """Get the encoding used for testing."""
    return onig_encoding

def set_output_encoding(enc=None):
    """Set the encoding used for showing the results.

    arguments:
      enc -- Encoding name or an instance of onigmo.OnigEncoding.
             If omitted, locale.getpreferredencoding() is used.
    """
    if enc is None:
        enc = locale.getpreferredencoding()

    def get_text_writer(fo, **kwargs):
        kw = dict(kwargs)
        kw.setdefault('errors', 'backslashreplace') # use \uXXXX style
        kw.setdefault('closefd', False)

        if sys.version_info[0] < 3:
            # Work around for Python 2.x
            # New line conversion isn't needed here. Done in somewhere else.
            writer = io.open(fo.fileno(), mode='w', newline='', **kw)
            write = writer.write    # save the original write() function
            enc = locale.getpreferredencoding()
            def convwrite(s):
                if isinstance(s, bytes):
                    write(s.decode(enc))    # convert to unistr
                else:
                    write(s)
                try:
                    writer.flush()  # needed on Windows
                except IOError:
                    pass
            writer.write = convwrite
        else:
            writer = io.open(fo.fileno(), mode='w', **kw)
        return writer

    sys.stdout = get_text_writer(sys.stdout, encoding=enc)
    sys.stderr = get_text_writer(sys.stderr, encoding=enc)


def set_default_warning_function():
    global _warn_func_ptr

    warning_enc = get_encoding_name(onig_encoding)
    if is_ascii_incompatible_encoding(warning_enc):
        warning_enc = 'ascii'
    def warn_func(str):
        print("warning: " + str.decode(warning_enc, 'replace'))

    _warn_func_ptr = onigmo.OnigWarnFunc(warn_func)
    onigmo.onig_set_warn_func(_warn_func_ptr)
    onigmo.onig_set_verb_warn_func(_warn_func_ptr)


def init(enc, outenc=None):
    """Setup test target encoding, output encoding and warning function.

    arguments:
      enc    -- Encoding used for testing.
      outenc -- Encoding used for showing messages.
    """
    set_encoding(enc)
    set_output_encoding(outenc)
    set_default_warning_function()


def main():
    # encoding of the test target
    enc = None
    if len(sys.argv) > 1:
        enc = sys.argv[1]

    # encoding of stdout/stderr
    outenc = None
    if len(sys.argv) > 2:
        outenc = sys.argv[2]

    # Initialization
    try:
        init(enc, outenc)
    except KeyError:
        print("test target encoding error")
        print("Usage: python testpy.py [test target encoding] [output encoding]")
        sys.exit()

    print(onigmo.onig_copyright())

    # Copied from onig-5.9.2/testc.c
    #   '?\?' which is used to avoid trigraph is replaced by '??'.
    #   Match positions are specified by unit of character instead of byte.

    x2("", "", 0, 0);
    x2("^", "", 0, 0);
    x2("$", "", 0, 0);
    x2("\\G", "", 0, 0);
    x2("\\A", "", 0, 0);
    x2("\\Z", "", 0, 0);
    x2("\\z", "", 0, 0);
    x2("^$", "", 0, 0);
    x2("\\ca", "\001", 0, 1);
    x2("\\C-b", "\002", 0, 1);
    x2("\\c\\\\", "\034", 0, 1);
    x2("q[\\c\\\\]", "q\034", 0, 2);
    x2("", "a", 0, 0);
    x2("a", "a", 0, 1);
    if onig_encoding == onigmo.ONIG_ENCODING_UTF16_LE:
        x2("\\x61\\x00", "a", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF16_BE:
        x2("\\x00\\x61", "a", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF32_LE:
        x2("\\x61\\x00\\x00\\x00", "a", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF32_BE:
        x2("\\x00\\x00\\x00\\x61", "a", 0, 1);
    else:
        x2("\\x61", "a", 0, 1);
    x2("aa", "aa", 0, 2);
    x2("aaa", "aaa", 0, 3);
    x2("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, 35);
    x2("ab", "ab", 0, 2);
    x2("b", "ab", 1, 2);
    x2("bc", "abc", 1, 3);
    x2("(?i:#RET#)", "#INS##RET#", 5, 10);
    if onig_encoding == onigmo.ONIG_ENCODING_UTF16_LE:
        x2("\\17\\00", "\017", 0, 1);
        x2("\\x1f\\x00", "\x1f", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF16_BE:
        x2("\\00\\17", "\017", 0, 1);
        x2("\\x00\\x1f", "\x1f", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF32_LE:
        x2("\\17\\00\\00\\00", "\017", 0, 1);
        x2("\\x1f\\x00\\x00\\x00", "\x1f", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF32_BE:
        x2("\\00\\00\\00\\17", "\017", 0, 1);
        x2("\\x00\\x00\\x00\\x1f", "\x1f", 0, 1);
    else:
        x2("\\17", "\017", 0, 1);
        x2("\\x1f", "\x1f", 0, 1);
    x2("a(?#....\\\\JJJJ)b", "ab", 0, 2);
    x2("(?x)  G (o O(?-x)oO) g L", "GoOoOgLe", 0, 7);
    x2(".", "a", 0, 1);
    n(".", "");
    x2("..", "ab", 0, 2);
    x2("\\w", "e", 0, 1);
    n("\\W", "e");
    x2("\\s", " ", 0, 1);
    x2("\\S", "b", 0, 1);
    x2("\\d", "4", 0, 1);
    n("\\D", "4");
    x2("\\b", "z ", 0, 0);
    x2("\\b", " z", 1, 1);
    x2("\\B", "zz ", 1, 1);
    x2("\\B", "z ", 2, 2);
    x2("\\B", " z", 0, 0);
    x2("[ab]", "b", 0, 1);
    n("[ab]", "c");
    x2("[a-z]", "t", 0, 1);
    n("[^a]", "a");
    x2("[^a]", "\n", 0, 1);
    x2("[]]", "]", 0, 1);
    n("[^]]", "]");
    x2("[\\^]+", "0^^1", 1, 3);
    x2("[b-]", "b", 0, 1);
    x2("[b-]", "-", 0, 1);
    x2("[\\w]", "z", 0, 1);
    n("[\\w]", " ");
    x2("[\\W]", "b$", 1, 2);
    x2("[\\d]", "5", 0, 1);
    n("[\\d]", "e");
    x2("[\\D]", "t", 0, 1);
    n("[\\D]", "3");
    x2("[\\s]", " ", 0, 1);
    n("[\\s]", "a");
    x2("[\\S]", "b", 0, 1);
    n("[\\S]", " ");
    x2("[\\w\\d]", "2", 0, 1);
    n("[\\w\\d]", " ");
    x2("[[:upper:]]", "B", 0, 1);
    x2("[*[:xdigit:]+]", "+", 0, 1);
    x2("[*[:xdigit:]+]", "GHIKK-9+*", 6, 7);
    x2("[*[:xdigit:]+]", "-@^+", 3, 4);
    n("[[:upper]]", "A");
    x2("[[:upper]]", ":", 0, 1);
    if onig_encoding == onigmo.ONIG_ENCODING_UTF16_LE:
        x2("[\\044\\000-\\047\\000]", "\046", 0, 1);
        x2("[\\x5a\\x00-\\x5c\\x00]", "\x5b", 0, 1);
        x2("[\\x6A\\x00-\\x6D\\x00]", "\x6c", 0, 1);
        n("[\\x6A\\x00-\\x6D\\x00]", "\x6E");
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF16_BE:
        x2("[\\000\\044-\\000\\047]", "\046", 0, 1);
        x2("[\\x00\\x5a-\\x00\\x5c]", "\x5b", 0, 1);
        x2("[\\x00\\x6A-\\x00\\x6D]", "\x6c", 0, 1);
        n("[\\x00\\x6A-\\x00\\x6D]", "\x6E");
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF32_LE:
        x2("[\\044\\000\\000\\000-\\047\\000\\000\\000]", "\046", 0, 1);
        x2("[\\x5a\\x00\\x00\\x00-\\x5c\\x00\\x00\\x00]", "\x5b", 0, 1);
        x2("[\\x6A\\x00\\x00\\x00-\\x6D\\x00\\x00\\x00]", "\x6c", 0, 1);
        n("[\\x6A\\x00\\x00\\x00-\\x6D\\x00\\x00\\x00]", "\x6E");
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF32_BE:
        x2("[\\000\\000\\000\\044-\\000\\000\\000\\047]", "\046", 0, 1);
        x2("[\\x00\\x00\\x00\\x5a-\\x00\\x00\\x00\\x5c]", "\x5b", 0, 1);
        x2("[\\x00\\x00\\x00\\x6A-\\x00\\x00\\x00\\x6D]", "\x6c", 0, 1);
        n("[\\x00\\x00\\x00\\x6A-\\x00\\x00\\x00\\x6D]", "\x6E");
    else:
        x2("[\\044-\\047]", "\046", 0, 1);
        x2("[\\x5a-\\x5c]", "\x5b", 0, 1);
        x2("[\\x6A-\\x6D]", "\x6c", 0, 1);
        n("[\\x6A-\\x6D]", "\x6E");
    n("^[0-9A-F]+ 0+ UNDEF ", "75F 00000000 SECT14A notype ()    External    | _rb_apply");
    x2("[\\[]", "[", 0, 1);
    x2("[\\]]", "]", 0, 1);
    x2("[&]", "&", 0, 1);
    x2("[[ab]]", "b", 0, 1);
    x2("[[ab]c]", "c", 0, 1);
    n("[[^a]]", "a");
    n("[^[a]]", "a");
    x2("[[ab]&&bc]", "b", 0, 1);
    n("[[ab]&&bc]", "a");
    n("[[ab]&&bc]", "c");
    x2("[a-z&&b-y&&c-x]", "w", 0, 1);
    n("[^a-z&&b-y&&c-x]", "w");
    x2("[[^a&&a]&&a-z]", "b", 0, 1);
    n("[[^a&&a]&&a-z]", "a");
    x2("[[^a-z&&bcdef]&&[^c-g]]", "h", 0, 1);
    n("[[^a-z&&bcdef]&&[^c-g]]", "c");
    x2("[^[^abc]&&[^cde]]", "c", 0, 1);
    x2("[^[^abc]&&[^cde]]", "e", 0, 1);
    n("[^[^abc]&&[^cde]]", "f");
    x2("[a-&&-a]", "-", 0, 1);
    n("[a\\-&&\\-a]", "&");
    n("\\wabc", " abc");
    x2("a\\Wbc", "a bc", 0, 4);
    x2("a.b.c", "aabbc", 0, 5);
    x2(".\\wb\\W..c", "abb bcc", 0, 7);
    x2("\\s\\wzzz", " zzzz", 0, 5);
    x2("aa.b", "aabb", 0, 4);
    n(".a", "ab");
    x2(".a", "aa", 0, 2);
    x2("^a", "a", 0, 1);
    x2("^a$", "a", 0, 1);
    x2("^\\w$", "a", 0, 1);
    n("^\\w$", " ");
    x2("^\\wab$", "zab", 0, 3);
    x2("^\\wabcdef$", "zabcdef", 0, 7);
    x2("^\\w...def$", "zabcdef", 0, 7);
    x2("\\w\\w\\s\\Waaa\\d", "aa  aaa4", 0, 8);
    x2("\\A\\Z", "", 0, 0);
    x2("\\Axyz", "xyz", 0, 3);
    x2("xyz\\Z", "xyz", 0, 3);
    x2("xyz\\z", "xyz", 0, 3);
    x2("a\\Z", "a", 0, 1);
    x2("\\Gaz", "az", 0, 2);
    n("\\Gz", "bza");
    n("az\\G", "az");
    n("az\\A", "az");
    n("a\\Az", "az");
    x2("\\^\\$", "^$", 0, 2);
    x2("^x?y", "xy", 0, 2);
    x2("^(x?y)", "xy", 0, 2);
    x2("\\w", "_", 0, 1);
    n("\\W", "_");
    x2("(?=z)z", "z", 0, 1);
    n("(?=z).", "a");
    x2("(?!z)a", "a", 0, 1);
    n("(?!z)a", "z");
    x2("(?i:a)", "a", 0, 1);
    x2("(?i:a)", "A", 0, 1);
    x2("(?i:A)", "a", 0, 1);
    n("(?i:A)", "b");
    x2("(?i:[A-Z])", "a", 0, 1);
    x2("(?i:[f-m])", "H", 0, 1);
    x2("(?i:[f-m])", "h", 0, 1);
    n("(?i:[f-m])", "e");
    x2("(?i:[A-c])", "D", 0, 1);
    n("(?i:[^a-z])", "A");
    n("(?i:[^a-z])", "a");
    x2("(?i:[!-k])", "Z", 0, 1);
    x2("(?i:[!-k])", "7", 0, 1);
    x2("(?i:[T-}])", "b", 0, 1);
    x2("(?i:[T-}])", "{", 0, 1);
    x2("(?i:\\?a)", "?A", 0, 2);
    x2("(?i:\\*A)", "*a", 0, 2);
    n(".", "\n");
    x2("(?m:.)", "\n", 0, 1);
    x2("(?m:a.)", "a\n", 0, 2);
    x2("(?m:.b)", "a\nb", 1, 3);
    x2(".*abc", "dddabdd\nddabc", 8, 13);
    x2("(?m:.*abc)", "dddabddabc", 0, 10);
    n("(?i)(?-i)a", "A");
    n("(?i)(?-i:a)", "A");
    x2("a?", "", 0, 0);
    x2("a?", "b", 0, 0);
    x2("a?", "a", 0, 1);
    x2("a*", "", 0, 0);
    x2("a*", "a", 0, 1);
    x2("a*", "aaa", 0, 3);
    x2("a*", "baaaa", 0, 0);
    n("a+", "");
    x2("a+", "a", 0, 1);
    x2("a+", "aaaa", 0, 4);
    x2("a+", "aabbb", 0, 2);
    x2("a+", "baaaa", 1, 5);
    x2(".?", "", 0, 0);
    x2(".?", "f", 0, 1);
    x2(".?", "\n", 0, 0);
    x2(".*", "", 0, 0);
    x2(".*", "abcde", 0, 5);
    x2(".+", "z", 0, 1);
    x2(".+", "zdswer\n", 0, 6);
    x2("(.*)a\\1f", "babfbac", 0, 4);
    x2("(.*)a\\1f", "bacbabf", 3, 7);
    x2("((.*)a\\2f)", "bacbabf", 3, 7);
    x2("(.*)a\\1f", "baczzzzzz\nbazz\nzzzzbabf", 19, 23);
    x2("a|b", "a", 0, 1);
    x2("a|b", "b", 0, 1);
    x2("|a", "a", 0, 0);
    x2("(|a)", "a", 0, 0);
    x2("ab|bc", "ab", 0, 2);
    x2("ab|bc", "bc", 0, 2);
    x2("z(?:ab|bc)", "zbc", 0, 3);
    x2("a(?:ab|bc)c", "aabc", 0, 4);
    x2("ab|(?:ac|az)", "az", 0, 2);
    x2("a|b|c", "dc", 1, 2);
    x2("a|b|cd|efg|h|ijk|lmn|o|pq|rstuvwx|yz", "pqr", 0, 2);
    n("a|b|cd|efg|h|ijk|lmn|o|pq|rstuvwx|yz", "mn");
    x2("a|^z", "ba", 1, 2);
    x2("a|^z", "za", 0, 1);
    x2("a|\\Gz", "bza", 2, 3);
    x2("a|\\Gz", "za", 0, 1);
    x2("a|\\Az", "bza", 2, 3);
    x2("a|\\Az", "za", 0, 1);
    x2("a|b\\Z", "ba", 1, 2);
    x2("a|b\\Z", "b", 0, 1);
    x2("a|b\\z", "ba", 1, 2);
    x2("a|b\\z", "b", 0, 1);
    x2("\\w|\\s", " ", 0, 1);
    n("\\w|\\w", " ");
    x2("\\w|%", "%", 0, 1);
    x2("\\w|[&$]", "&", 0, 1);
    x2("[b-d]|[^e-z]", "a", 0, 1);
    x2("(?:a|[c-f])|bz", "dz", 0, 1);
    x2("(?:a|[c-f])|bz", "bz", 0, 2);
    x2("abc|(?=zz)..f", "zzf", 0, 3);
    x2("abc|(?!zz)..f", "abf", 0, 3);
    x2("(?=za)..a|(?=zz)..a", "zza", 0, 3);
    n("(?>a|abd)c", "abdc");
    x2("(?>abd|a)c", "abdc", 0, 4);
    x2("a?|b", "a", 0, 1);
    x2("a?|b", "b", 0, 0);
    x2("a?|b", "", 0, 0);
    x2("a*|b", "aa", 0, 2);
    x2("a*|b*", "ba", 0, 0);
    x2("a*|b*", "ab", 0, 1);
    x2("a+|b*", "", 0, 0);
    x2("a+|b*", "bbb", 0, 3);
    x2("a+|b*", "abbb", 0, 1);
    n("a+|b+", "");
    x2("(a|b)?", "b", 0, 1);
    x2("(a|b)*", "ba", 0, 2);
    x2("(a|b)+", "bab", 0, 3);
    x2("(ab|ca)+", "caabbc", 0, 4);
    x2("(ab|ca)+", "aabca", 1, 5);
    x2("(ab|ca)+", "abzca", 0, 2);
    x2("(a|bab)+", "ababa", 0, 5);
    x2("(a|bab)+", "ba", 1, 2);
    x2("(a|bab)+", "baaaba", 1, 4);
    x2("(?:a|b)(?:a|b)", "ab", 0, 2);
    x2("(?:a*|b*)(?:a*|b*)", "aaabbb", 0, 3);
    x2("(?:a*|b*)(?:a+|b+)", "aaabbb", 0, 6);
    x2("(?:a+|b+){2}", "aaabbb", 0, 6);
    x2("h{0,}", "hhhh", 0, 4);
    x2("(?:a+|b+){1,2}", "aaabbb", 0, 6);
    n("ax{2}*a", "0axxxa1");
    n("a.{0,2}a", "0aXXXa0");
    n("a.{0,2}?a", "0aXXXa0");
    n("a.{0,2}?a", "0aXXXXa0");
    x2("^a{2,}?a$", "aaa", 0, 3);
    x2("^[a-z]{2,}?$", "aaa", 0, 3);
    x2("(?:a+|\\Ab*)cc", "cc", 0, 2);
    n("(?:a+|\\Ab*)cc", "abcc");
    x2("(?:^a+|b+)*c", "aabbbabc", 6, 8);
    x2("(?:^a+|b+)*c", "aabbbbc", 0, 7);
    x2("a|(?i)c", "C", 0, 1);
    x2("(?i)c|a", "C", 0, 1);
    x2("(?i)c|a", "A", 0, 1);
    x2("(?i:c)|a", "C", 0, 1);
    n("(?i:c)|a", "A");
    x2("[abc]?", "abc", 0, 1);
    x2("[abc]*", "abc", 0, 3);
    x2("[^abc]*", "abc", 0, 0);
    n("[^abc]+", "abc");
    x2("a??", "aaa", 0, 0);
    x2("ba??b", "bab", 0, 3);
    x2("a*?", "aaa", 0, 0);
    x2("ba*?", "baa", 0, 1);
    x2("ba*?b", "baab", 0, 4);
    x2("a+?", "aaa", 0, 1);
    x2("ba+?", "baa", 0, 2);
    x2("ba+?b", "baab", 0, 4);
    x2("(?:a?)??", "a", 0, 0);
    x2("(?:a??)?", "a", 0, 0);
    x2("(?:a?)+?", "aaa", 0, 1);
    x2("(?:a+)??", "aaa", 0, 0);
    x2("(?:a+)??b", "aaab", 0, 4);
    x2("(?:ab)?{2}", "", 0, 0);
    x2("(?:ab)?{2}", "ababa", 0, 4);
    x2("(?:ab)*{0}", "ababa", 0, 0);
    x2("(?:ab){3,}", "abababab", 0, 8);
    n("(?:ab){3,}", "abab");
    x2("(?:ab){2,4}", "ababab", 0, 6);
    x2("(?:ab){2,4}", "ababababab", 0, 8);
    x2("(?:ab){2,4}?", "ababababab", 0, 4);
    x2("(?:ab){,}", "ab{,}", 0, 5);
    x2("(?:abc)+?{2}", "abcabcabc", 0, 6);
    x2("(?:X*)(?i:xa)", "XXXa", 0, 4);
    x2("(d+)([^abc]z)", "dddz", 0, 4);
    x2("([^abc]*)([^abc]z)", "dddz", 0, 4);
    x2("(\\w+)(\\wz)", "dddz", 0, 4);
    x3("(a)", "a", 0, 1, 1);
    x3("(ab)", "ab", 0, 2, 1);
    x2("((ab))", "ab", 0, 2);
    x3("((ab))", "ab", 0, 2, 1);
    x3("((ab))", "ab", 0, 2, 2);
    x3("((((((((((((((((((((ab))))))))))))))))))))", "ab", 0, 2, 20);
    x3("(ab)(cd)", "abcd", 0, 2, 1);
    x3("(ab)(cd)", "abcd", 2, 4, 2);
    x3("()(a)bc(def)ghijk", "abcdefghijk", 3, 6, 3);
    x3("(()(a)bc(def)ghijk)", "abcdefghijk", 3, 6, 4);
    x2("(^a)", "a", 0, 1);
    x3("(a)|(a)", "ba", 1, 2, 1);
    x3("(^a)|(a)", "ba", 1, 2, 2);
    x3("(a?)", "aaa", 0, 1, 1);
    x3("(a*)", "aaa", 0, 3, 1);
    x3("(a*)", "", 0, 0, 1);
    x3("(a+)", "aaaaaaa", 0, 7, 1);
    x3("(a+|b*)", "bbbaa", 0, 3, 1);
    x3("(a+|b?)", "bbbaa", 0, 1, 1);
    x3("(abc)?", "abc", 0, 3, 1);
    x3("(abc)*", "abc", 0, 3, 1);
    x3("(abc)+", "abc", 0, 3, 1);
    x3("(xyz|abc)+", "abc", 0, 3, 1);
    x3("([xyz][abc]|abc)+", "abc", 0, 3, 1);
    x3("((?i:abc))", "AbC", 0, 3, 1);
    x2("(abc)(?i:\\1)", "abcABC", 0, 6);
    x3("((?m:a.c))", "a\nc", 0, 3, 1);
    x3("((?=az)a)", "azb", 0, 1, 1);
    x3("abc|(.abd)", "zabd", 0, 4, 1);
    x2("(?:abc)|(ABC)", "abc", 0, 3);
    x3("(?i:(abc))|(zzz)", "ABC", 0, 3, 1);
    x3("a*(.)", "aaaaz", 4, 5, 1);
    x3("a*?(.)", "aaaaz", 0, 1, 1);
    x3("a*?(c)", "aaaac", 4, 5, 1);
    x3("[bcd]a*(.)", "caaaaz", 5, 6, 1);
    x3("(\\Abb)cc", "bbcc", 0, 2, 1);
    n("(\\Abb)cc", "zbbcc");
    x3("(^bb)cc", "bbcc", 0, 2, 1);
    n("(^bb)cc", "zbbcc");
    x3("cc(bb$)", "ccbb", 2, 4, 1);
    n("cc(bb$)", "ccbbb");
    n("(\\1)", "");
    n("\\1(a)", "aa");
    n("(a(b)\\1)\\2+", "ababb");
    n("(?:(?:\\1|z)(a))+$", "zaa");
    x2("(?:(?:\\1|z)(a))+$", "zaaa", 0, 4);
    x2("(a)(?=\\1)", "aa", 0, 1);
    n("(a)$|\\1", "az");
    x2("(a)\\1", "aa", 0, 2);
    n("(a)\\1", "ab");
    x2("(a?)\\1", "aa", 0, 2);
    x2("(a??)\\1", "aa", 0, 0);
    x2("(a*)\\1", "aaaaa", 0, 4);
    x3("(a*)\\1", "aaaaa", 0, 2, 1);
    x2("a(b*)\\1", "abbbb", 0, 5);
    x2("a(b*)\\1", "ab", 0, 1);
    x2("(a*)(b*)\\1\\2", "aaabbaaabb", 0, 10);
    x2("(a*)(b*)\\2", "aaabbbb", 0, 7);
    x2("(((((((a*)b))))))c\\7", "aaabcaaa", 0, 8);
    x3("(((((((a*)b))))))c\\7", "aaabcaaa", 0, 3, 7);
    x2("(a)(b)(c)\\2\\1\\3", "abcbac", 0, 6);
    x2("([a-d])\\1", "cc", 0, 2);
    x2("(\\w\\d\\s)\\1", "f5 f5 ", 0, 6);
    n("(\\w\\d\\s)\\1", "f5 f5");
    x2("(who|[a-c]{3})\\1", "whowho", 0, 6);
    x2("...(who|[a-c]{3})\\1", "abcwhowho", 0, 9);
    x2("(who|[a-c]{3})\\1", "cbccbc", 0, 6);
    x2("(^a)\\1", "aa", 0, 2);
    n("(^a)\\1", "baa");
    n("(a$)\\1", "aa");
    n("(ab\\Z)\\1", "ab");
    x2("(a*\\Z)\\1", "a", 1, 1);
    x2(".(a*\\Z)\\1", "ba", 1, 2);
    x3("(.(abc)\\2)", "zabcabc", 0, 7, 1);
    x3("(.(..\\d.)\\2)", "z12341234", 0, 9, 1);
    x2("((?i:az))\\1", "AzAz", 0, 4);
    n("((?i:az))\\1", "Azaz");
    x2("(?<=a)b", "ab", 1, 2);
    n("(?<=a)b", "bb");
    x2("(?<=a|b)b", "bb", 1, 2);
    x2("(?<=a|bc)b", "bcb", 2, 3);
    x2("(?<=a|bc)b", "ab", 1, 2);
    x2("(?<=a|bc||defghij|klmnopq|r)z", "rz", 1, 2);
    x2("(a)\\g<1>", "aa", 0, 2);
    x2("(?<!a)b", "cb", 1, 2);
    n("(?<!a)b", "ab");
    x2("(?<!a|bc)b", "bbb", 0, 1);
    n("(?<!a|bc)z", "bcz");
    x2("(?<name1>a)", "a", 0, 1);
    x2("(?<name_2>ab)\\g<name_2>", "abab", 0, 4);
    x2("(?<name_3>.zv.)\\k<name_3>", "azvbazvb", 0, 8);
    x2("(?<=\\g<ab>)|-\\zEND (?<ab>XyZ)", "XyZ", 3, 3);
    x2("(?<n>|a\\g<n>)+", "", 0, 0);
    x2("(?<n>|\\(\\g<n>\\))+$", "()(())", 0, 6);
    x3("\\g<n>(?<n>.){0}", "X", 0, 1, 1);
    x2("\\g<n>(abc|df(?<n>.YZ){2,8}){0}", "XYZ", 0, 3);
    x2("\\A(?<n>(a\\g<n>)|)\\z", "aaaa", 0, 4);
    x2("(?<n>|\\g<m>\\g<n>)\\z|\\zEND (?<m>a|(b)\\g<m>)", "bbbbabba", 0, 8);
    x2("(?<name1240>\\w+\\sx)a+\\k<name1240>", "  fg xaaaaaaaafg x", 2, 18);
    x3("(z)()()(?<_9>a)\\g<_9>", "zaa", 2, 3, 1);
    x2("(.)(((?<_>a)))\\k<_>", "zaa", 0, 3);
    x2("((?<name1>\\d)|(?<name2>\\w))(\\k<name1>|\\k<name2>)", "ff", 0, 2);
    x2("(?:(?<x>)|(?<x>efg))\\k<x>", "", 0, 0);
    x2("(?:(?<x>abc)|(?<x>efg))\\k<x>", "abcefgefg", 3, 9);
    n("(?:(?<x>abc)|(?<x>efg))\\k<x>", "abcefg");
    x2("(?:(?<n1>.)|(?<n1>..)|(?<n1>...)|(?<n1>....)|(?<n1>.....)|(?<n1>......)|(?<n1>.......)|(?<n1>........)|(?<n1>.........)|(?<n1>..........)|(?<n1>...........)|(?<n1>............)|(?<n1>.............)|(?<n1>..............))\\k<n1>$", "a-pyumpyum", 2, 10);
    x3("(?:(?<n1>.)|(?<n1>..)|(?<n1>...)|(?<n1>....)|(?<n1>.....)|(?<n1>......)|(?<n1>.......)|(?<n1>........)|(?<n1>.........)|(?<n1>..........)|(?<n1>...........)|(?<n1>............)|(?<n1>.............)|(?<n1>..............))\\k<n1>$", "xxxxabcdefghijklmnabcdefghijklmn", 4, 18, 14);
    x3("(?<name1>)(?<name2>)(?<name3>)(?<name4>)(?<name5>)(?<name6>)(?<name7>)(?<name8>)(?<name9>)(?<name10>)(?<name11>)(?<name12>)(?<name13>)(?<name14>)(?<name15>)(?<name16>aaa)(?<name17>)$", "aaa", 0, 3, 16);
    x2("(?<foo>a|\\(\\g<foo>\\))", "a", 0, 1);
    x2("(?<foo>a|\\(\\g<foo>\\))", "((((((a))))))", 0, 13);
    x3("(?<foo>a|\\(\\g<foo>\\))", "((((((((a))))))))", 0, 17, 1);
    x2("\\g<bar>|\\zEND(?<bar>.*abc$)", "abcxxxabc", 0, 9);
    x2("\\g<1>|\\zEND(.a.)", "bac", 0, 3);
    x3("\\g<_A>\\g<_A>|\\zEND(.a.)(?<_A>.b.)", "xbxyby", 3, 6, 1);
    x2("\\A(?:\\g<pon>|\\g<pan>|\\zEND  (?<pan>a|c\\g<pon>c)(?<pon>b|d\\g<pan>d))$", "cdcbcdc", 0, 7);
    x2("\\A(?<n>|a\\g<m>)\\z|\\zEND (?<m>\\g<n>)", "aaaa", 0, 4);
    x2("(?<n>(a|b\\g<n>c){3,5})", "baaaaca", 1, 5);
    x2("(?<n>(a|b\\g<n>c){3,5})", "baaaacaaaaa", 0, 10);
    x2("(?<pare>\\(([^\\(\\)]++|\\g<pare>)*+\\))", "((a))", 0, 5);
    x2("()*\\1", "", 0, 0);
    x2("(?:()|())*\\1\\2", "", 0, 0);
    x3("(?:\\1a|())*", "a", 0, 0, 1);
    x2("x((.)*)*x", "0x1x2x3", 1, 6);
    x2("x((.)*)*x(?i:\\1)\\Z", "0x1x2x1X2", 1, 9);
    x2("(?:()|()|()|()|()|())*\\2\\5", "", 0, 0);
    x2("(?:()|()|()|(x)|()|())*\\2b\\5", "b", 0, 1);
    if onig_encoding == onigmo.ONIG_ENCODING_UTF16_LE:
        x2("\\xFA\\x8F", "\u8ffa", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF16_BE:
        x2("\\x8F\\xFA", "\u8ffa", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF32_LE:
        x2("\\xFA\\x8F\\x00\\x00", "\u8ffa", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF32_BE:
        x2("\\x00\\x00\\x8F\\xFA", "\u8ffa", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_UTF8:
        x2("\\xE8\\xBF\\xBA", "\u8ffa", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_SJIS or \
            onig_encoding == onigmo.ONIG_ENCODING_CP932:
        x2("\\xE7\\x92", "\u8ffa", 0, 1);
    elif onig_encoding == onigmo.ONIG_ENCODING_EUC_JP:
        x2("\\xED\\xF2", "\u8ffa", 0, 1); # "迺"
    x2("", "あ", 0, 0);
    x2("あ", "あ", 0, 1);
    n("い", "あ");
    x2("うう", "うう", 0, 2);
    x2("あいう", "あいう", 0, 3);
    x2("こここここここここここここここここここここここここここここここここここ", "こここここここここここここここここここここここここここここここここここ", 0, 35);
    x2("あ", "いあ", 1, 2);
    x2("いう", "あいう", 1, 3);
#    x2(b"\\xca\\xb8", b"\xca\xb8", 0, 2);   # "文"
    x2(".", "あ", 0, 1);
    x2("..", "かき", 0, 2);
    x2("\\w", "お", 0, 1);
    n("\\W", "あ");
    x2("[\\W]", "う$", 1, 2);
    x2("\\S", "そ", 0, 1);
    x2("\\S", "漢", 0, 1);
    x2("\\b", "気 ", 0, 0);
    x2("\\b", " ほ", 1, 1);
    x2("\\B", "せそ ", 1, 1);
    x2("\\B", "う ", 2, 2);
    x2("\\B", " い", 0, 0);
    x2("[たち]", "ち", 0, 1);
    n("[なに]", "ぬ");
    x2("[う-お]", "え", 0, 1);
    n("[^け]", "け");
    x2("[\\w]", "ね", 0, 1);
    n("[\\d]", "ふ");
    x2("[\\D]", "は", 0, 1);
    n("[\\s]", "く");
    x2("[\\S]", "へ", 0, 1);
    x2("[\\w\\d]", "よ", 0, 1);
    x2("[\\w\\d]", "   よ", 3, 4);
    n("\\w鬼車", " 鬼車");
    x2("鬼\\W車", "鬼 車", 0, 3);
    x2("あ.い.う", "ああいいう", 0, 5);
    x2(".\\wう\\W..ぞ", "えうう うぞぞ", 0, 7);
    x2("\\s\\wこここ", " ここここ", 0, 5);
    x2("ああ.け", "ああけけ", 0, 4);
    n(".い", "いえ");
    x2(".お", "おお", 0, 2);
    x2("^あ", "あ", 0, 1);
    x2("^む$", "む", 0, 1);
    x2("^\\w$", "に", 0, 1);
    x2("^\\wかきくけこ$", "zかきくけこ", 0, 6);
    x2("^\\w...うえお$", "zあいううえお", 0, 7);
    x2("\\w\\w\\s\\Wおおお\\d", "aお  おおお4", 0, 8);
    x2("\\Aたちつ", "たちつ", 0, 3);
    x2("むめも\\Z", "むめも", 0, 3);
    x2("かきく\\z", "かきく", 0, 3);
    x2("かきく\\Z", "かきく\n", 0, 3);
    x2("\\Gぽぴ", "ぽぴ", 0, 2);
    n("\\Gえ", "うえお");
    n("とて\\G", "とて");
    n("まみ\\A", "まみ");
    n("ま\\Aみ", "まみ");
    x2("(?=せ)せ", "せ", 0, 1);
    n("(?=う).", "い");
    x2("(?!う)か", "か", 0, 1);
    n("(?!と)あ", "と");
    x2("(?i:あ)", "あ", 0, 1);
    x2("(?i:ぶべ)", "ぶべ", 0, 2);
    n("(?i:い)", "う");
    x2("(?m:よ.)", "よ\n", 0, 2);
    x2("(?m:.め)", "ま\nめ", 1, 3);
    x2("あ?", "", 0, 0);
    x2("変?", "化", 0, 0);
    x2("変?", "変", 0, 1);
    x2("量*", "", 0, 0);
    x2("量*", "量", 0, 1);
    x2("子*", "子子子", 0, 3);
    x2("馬*", "鹿馬馬馬馬", 0, 0);
    n("山+", "");
    x2("河+", "河", 0, 1);
    x2("時+", "時時時時", 0, 4);
    x2("え+", "ええううう", 0, 2);
    x2("う+", "おうううう", 1, 5);
    x2(".?", "た", 0, 1);
    x2(".*", "ぱぴぷぺ", 0, 4);
    x2(".+", "ろ", 0, 1);
    x2(".+", "いうえか\n", 0, 4);
    x2("あ|い", "あ", 0, 1);
    x2("あ|い", "い", 0, 1);
    x2("あい|いう", "あい", 0, 2);
    x2("あい|いう", "いう", 0, 2);
    x2("を(?:かき|きく)", "をかき", 0, 3);
    x2("を(?:かき|きく)け", "をきくけ", 0, 4);
    x2("あい|(?:あう|あを)", "あを", 0, 2);
    x2("あ|い|う", "えう", 1, 2);
    x2("あ|い|うえ|おかき|く|けこさ|しすせ|そ|たち|つてとなに|ぬね", "しすせ", 0, 3);
    n("あ|い|うえ|おかき|く|けこさ|しすせ|そ|たち|つてとなに|ぬね", "すせ");
    x2("あ|^わ", "ぶあ", 1, 2);
    x2("あ|^を", "をあ", 0, 1);
    x2("鬼|\\G車", "け車鬼", 2, 3);
    x2("鬼|\\G車", "車鬼", 0, 1);
    x2("鬼|\\A車", "b車鬼", 2, 3);
    x2("鬼|\\A車", "車", 0, 1);
    x2("鬼|車\\Z", "車鬼", 1, 2);
    x2("鬼|車\\Z", "車", 0, 1);
    x2("鬼|車\\Z", "車\n", 0, 1);
    x2("鬼|車\\z", "車鬼", 1, 2);
    x2("鬼|車\\z", "車", 0, 1);
    x2("\\w|\\s", "お", 0, 1);
    x2("\\w|%", "%お", 0, 1);
    x2("\\w|[&$]", "う&", 0, 1);
    x2("[い-け]", "う", 0, 1);
    x2("[い-け]|[^か-こ]", "あ", 0, 1);
    x2("[い-け]|[^か-こ]", "か", 0, 1);
    x2("[^あ]", "\n", 0, 1);
    x2("(?:あ|[う-き])|いを", "うを", 0, 1);
    x2("(?:あ|[う-き])|いを", "いを", 0, 2);
    x2("あいう|(?=けけ)..ほ", "けけほ", 0, 3);
    x2("あいう|(?!けけ)..ほ", "あいほ", 0, 3);
    x2("(?=をあ)..あ|(?=をを)..あ", "ををあ", 0, 3);
    x2("(?<=あ|いう)い", "いうい", 2, 3);
    n("(?>あ|あいえ)う", "あいえう");
    x2("(?>あいえ|あ)う", "あいえう", 0, 4);
    x2("あ?|い", "あ", 0, 1);
    x2("あ?|い", "い", 0, 0);
    x2("あ?|い", "", 0, 0);
    x2("あ*|い", "ああ", 0, 2);
    x2("あ*|い*", "いあ", 0, 0);
    x2("あ*|い*", "あい", 0, 1);
    x2("[aあ]*|い*", "aあいいい", 0, 2);
    x2("あ+|い*", "", 0, 0);
    x2("あ+|い*", "いいい", 0, 3);
    x2("あ+|い*", "あいいい", 0, 1);
    x2("あ+|い*", "aあいいい", 0, 0);
    n("あ+|い+", "");
    x2("(あ|い)?", "い", 0, 1);
    x2("(あ|い)*", "いあ", 0, 2);
    x2("(あ|い)+", "いあい", 0, 3);
    x2("(あい|うあ)+", "うああいうえ", 0, 4);
    x2("(あい|うえ)+", "うああいうえ", 2, 6);
    x2("(あい|うあ)+", "ああいうあ", 1, 5);
    x2("(あい|うあ)+", "あいをうあ", 0, 2);
    x2("(あい|うあ)+", "$$zzzzあいをうあ", 6, 8);
    x2("(あ|いあい)+", "あいあいあ", 0, 5);
    x2("(あ|いあい)+", "いあ", 1, 2);
    x2("(あ|いあい)+", "いあああいあ", 1, 4);
    x2("(?:あ|い)(?:あ|い)", "あい", 0, 2);
    x2("(?:あ*|い*)(?:あ*|い*)", "あああいいい", 0, 3);
    x2("(?:あ*|い*)(?:あ+|い+)", "あああいいい", 0, 6);
    x2("(?:あ+|い+){2}", "あああいいい", 0, 6);
    x2("(?:あ+|い+){1,2}", "あああいいい", 0, 6);
    x2("(?:あ+|\\Aい*)うう", "うう", 0, 2);
    n("(?:あ+|\\Aい*)うう", "あいうう");
    x2("(?:^あ+|い+)*う", "ああいいいあいう", 6, 8);
    x2("(?:^あ+|い+)*う", "ああいいいいう", 0, 7);
    x2("う{0,}", "うううう", 0, 4);
    x2("あ|(?i)c", "C", 0, 1);
    x2("(?i)c|あ", "C", 0, 1);
    x2("(?i:あ)|a", "a", 0, 1);
    n("(?i:あ)|a", "A");
    x2("[あいう]?", "あいう", 0, 1);
    x2("[あいう]*", "あいう", 0, 3);
    x2("[^あいう]*", "あいう", 0, 0);
    n("[^あいう]+", "あいう");
    x2("あ??", "あああ", 0, 0);
    x2("いあ??い", "いあい", 0, 3);
    x2("あ*?", "あああ", 0, 0);
    x2("いあ*?", "いああ", 0, 1);
    x2("いあ*?い", "いああい", 0, 4);
    x2("あ+?", "あああ", 0, 1);
    x2("いあ+?", "いああ", 0, 2);
    x2("いあ+?い", "いああい", 0, 4);
    x2("(?:天?)??", "天", 0, 0);
    x2("(?:天??)?", "天", 0, 0);
    x2("(?:夢?)+?", "夢夢夢", 0, 1);
    x2("(?:風+)??", "風風風", 0, 0);
    x2("(?:雪+)??霜", "雪雪雪霜", 0, 4);
    x2("(?:あい)?{2}", "", 0, 0);
    x2("(?:鬼車)?{2}", "鬼車鬼車鬼", 0, 4);
    x2("(?:鬼車)*{0}", "鬼車鬼車鬼", 0, 0);
    x2("(?:鬼車){3,}", "鬼車鬼車鬼車鬼車", 0, 8);
    n("(?:鬼車){3,}", "鬼車鬼車");
    x2("(?:鬼車){2,4}", "鬼車鬼車鬼車", 0, 6);
    x2("(?:鬼車){2,4}", "鬼車鬼車鬼車鬼車鬼車", 0, 8);
    x2("(?:鬼車){2,4}?", "鬼車鬼車鬼車鬼車鬼車", 0, 4);
    x2("(?:鬼車){,}", "鬼車{,}", 0, 5);
    x2("(?:かきく)+?{2}", "かきくかきくかきく", 0, 6);
    x3("(火)", "火", 0, 1, 1);
    x3("(火水)", "火水", 0, 2, 1);
    x2("((時間))", "時間", 0, 2);
    x3("((風水))", "風水", 0, 2, 1);
    x3("((昨日))", "昨日", 0, 2, 2);
    x3("((((((((((((((((((((量子))))))))))))))))))))", "量子", 0, 2, 20);
    x3("(あい)(うえ)", "あいうえ", 0, 2, 1);
    x3("(あい)(うえ)", "あいうえ", 2, 4, 2);
    x3("()(あ)いう(えおか)きくけこ", "あいうえおかきくけこ", 3, 6, 3);
    x3("(()(あ)いう(えおか)きくけこ)", "あいうえおかきくけこ", 3, 6, 4);
    x3(".*(フォ)ン・マ(ン()シュタ)イン", "フォン・マンシュタイン", 5, 9, 2);
    x2("(^あ)", "あ", 0, 1);
    x3("(あ)|(あ)", "いあ", 1, 2, 1);
    x3("(^あ)|(あ)", "いあ", 1, 2, 2);
    x3("(あ?)", "あああ", 0, 1, 1);
    x3("(ま*)", "ままま", 0, 3, 1);
    x3("(と*)", "", 0, 0, 1);
    x3("(る+)", "るるるるるるる", 0, 7, 1);
    x3("(ふ+|へ*)", "ふふふへへ", 0, 3, 1);
    x3("(あ+|い?)", "いいいああ", 0, 1, 1);
    x3("(あいう)?", "あいう", 0, 3, 1);
    x3("(あいう)*", "あいう", 0, 3, 1);
    x3("(あいう)+", "あいう", 0, 3, 1);
    x3("(さしす|あいう)+", "あいう", 0, 3, 1);
    x3("([なにぬ][かきく]|かきく)+", "かきく", 0, 3, 1);
    x3("((?i:あいう))", "あいう", 0, 3, 1);
    x3("((?m:あ.う))", "あ\nう", 0, 3, 1);
    x3("((?=あん)あ)", "あんい", 0, 1, 1);
    x3("あいう|(.あいえ)", "んあいえ", 0, 4, 1);
    x3("あ*(.)", "ああああん", 4, 5, 1);
    x3("あ*?(.)", "ああああん", 0, 1, 1);
    x3("あ*?(ん)", "ああああん", 4, 5, 1);
    x3("[いうえ]あ*(.)", "えああああん", 5, 6, 1);
    x3("(\\Aいい)うう", "いいうう", 0, 2, 1);
    n("(\\Aいい)うう", "んいいうう");
    x3("(^いい)うう", "いいうう", 0, 2, 1);
    n("(^いい)うう", "んいいうう");
    x3("ろろ(るる$)", "ろろるる", 2, 4, 1);
    n("ろろ(るる$)", "ろろるるる");
    x2("(無)\\1", "無無", 0, 2);
    n("(無)\\1", "無武");
    x2("(空?)\\1", "空空", 0, 2);
    x2("(空??)\\1", "空空", 0, 0);
    x2("(空*)\\1", "空空空空空", 0, 4);
    x3("(空*)\\1", "空空空空空", 0, 2, 1);
    x2("あ(い*)\\1", "あいいいい", 0, 5);
    x2("あ(い*)\\1", "あい", 0, 1);
    x2("(あ*)(い*)\\1\\2", "あああいいあああいい", 0, 10);
    x2("(あ*)(い*)\\2", "あああいいいい", 0, 7);
    x3("(あ*)(い*)\\2", "あああいいいい", 3, 5, 2);
    x2("(((((((ぽ*)ぺ))))))ぴ\\7", "ぽぽぽぺぴぽぽぽ", 0, 8);
    x3("(((((((ぽ*)ぺ))))))ぴ\\7", "ぽぽぽぺぴぽぽぽ", 0, 3, 7);
    x2("(は)(ひ)(ふ)\\2\\1\\3", "はひふひはふ", 0, 6);
    x2("([き-け])\\1", "くく", 0, 2);
    x2("(\\w\\d\\s)\\1", "あ5 あ5 ", 0, 6);
    n("(\\w\\d\\s)\\1", "あ5 あ5");
    x2("(誰？|[あ-う]{3})\\1", "誰？誰？", 0, 4);
    x2("...(誰？|[あ-う]{3})\\1", "あaあ誰？誰？", 0, 7);
    x2("(誰？|[あ-う]{3})\\1", "ういうういう", 0, 6);
    x2("(^こ)\\1", "ここ", 0, 2);
    n("(^む)\\1", "めむむ");
    n("(あ$)\\1", "ああ");
    n("(あい\\Z)\\1", "あい");
    x2("(あ*\\Z)\\1", "あ", 1, 1);
    x2(".(あ*\\Z)\\1", "いあ", 1, 2);
    x3("(.(やいゆ)\\2)", "zやいゆやいゆ", 0, 7, 1);
    x3("(.(..\\d.)\\2)", "あ12341234", 0, 9, 1);
    x2("((?i:あvず))\\1", "あvずあvず", 0, 6);
    x2("(?<愚か>変|\\(\\g<愚か>\\))", "((((((変))))))", 0, 13);
    x2("\\A(?:\\g<阿_1>|\\g<云_2>|\\z終了  (?<阿_1>観|自\\g<云_2>自)(?<云_2>在|菩薩\\g<阿_1>菩薩))$", "菩薩自菩薩自在自菩薩自菩薩", 0, 13);
    x2("[[ひふ]]", "ふ", 0, 1);
    x2("[[いおう]か]", "か", 0, 1);
    n("[[^あ]]", "あ");
    n("[^[あ]]", "あ");
    x2("[^[^あ]]", "あ", 0, 1);
    x2("[[かきく]&&きく]", "く", 0, 1);
    n("[[かきく]&&きく]", "か");
    n("[[かきく]&&きく]", "け");
    x2("[あ-ん&&い-を&&う-ゑ]", "ゑ", 0, 1);
    n("[^あ-ん&&い-を&&う-ゑ]", "ゑ");
    x2("[[^あ&&あ]&&あ-ん]", "い", 0, 1);
    n("[[^あ&&あ]&&あ-ん]", "あ");
    x2("[[^あ-ん&&いうえお]&&[^う-か]]", "き", 0, 1);
    n("[[^あ-ん&&いうえお]&&[^う-か]]", "い");
    x2("[^[^あいう]&&[^うえお]]", "う", 0, 1);
    x2("[^[^あいう]&&[^うえお]]", "え", 0, 1);
    n("[^[^あいう]&&[^うえお]]", "か");
    x2("[あ-&&-あ]", "-", 0, 1);
    x2("[^[^a-zあいう]&&[^bcdefgうえお]q-w]", "え", 0, 1);
    x2("[^[^a-zあいう]&&[^bcdefgうえお]g-w]", "f", 0, 1);
    x2("[^[^a-zあいう]&&[^bcdefgうえお]g-w]", "g", 0, 1);
    n("[^[^a-zあいう]&&[^bcdefgうえお]g-w]", "2");
    x2("a<b>バージョンのダウンロード<\\/b>", "a<b>バージョンのダウンロード</b>", 0, 20);
    x2(".<b>バージョンのダウンロード<\\/b>", "a<b>バージョンのダウンロード</b>", 0, 20);


    # additional test patterns
    if is_unicode_encoding(onig_encoding):
        x2("\\x{3042}\\x{3044}", "あい", 0, 2)
    elif onig_encoding == onigmo.ONIG_ENCODING_SJIS or \
            onig_encoding == onigmo.ONIG_ENCODING_CP932:
        x2("\\x{82a0}\\x{82A2}", "あい", 0, 2)
        x2("\\M-\\C-b\x50", "１", 0, 1)     # \x8250
    elif onig_encoding == onigmo.ONIG_ENCODING_EUC_JP:
        x2("\\x{a4a2}\\x{A4A4}", "あい", 0, 2)
    x2("\\p{Hiragana}\\p{Katakana}", "あイ", 0, 2)
    x2("(?m)^A.B$", "X\nA\nB\nZ", 2, 5)
    n("(?<!(?<=a)b|c)d", "abd")
    n("(?<!(?<=a)b|c)d", "cd")
    x2("(?<!(?<=a)b|c)d", "bd", 1, 2)
    x2("(a){2}z", "aaz", 0, 3)
    x2("(?<=a).*b", "aab", 1, 3)
    x2("(?!a).*b", "ab", 1, 2)
    x2("(?<=(?<!A)B)C", "BBC", 2, 3)
    n("(?<=(?<!A)B)C", "ABC")
    n("(?i)(?<!aa|b)c", "Aac")
    n("(?i)(?<!b|aa)c", "Aac")
    x2("(?<=\\babc)d", " abcd", 4, 5)
    x2("(?<=\\Babc)d", "aabcd", 4, 5)
    x2("a\\b?a", "aa", 0, 2)
    x2("[^x]*x", "aaax", 0, 4)
    x2("(?i)[\\x{0}-B]+", "\x00\x01\x02\x1f\x20@AaBbC", 0, 10)
    x2("(?i)a{2}", "AA", 0, 2)
    if is_unicode_encoding(onig_encoding):
        # The longest script name
        x2("\\p{Other_Default_Ignorable_Code_Point}+", "\u034F\uFFF8\U000E0FFF", 0, 3)
        # The longest block name
        x2("\\p{In_Unified_Canadian_Aboriginal_Syllabics_Extended}+", "\u18B0\u18FF", 0, 2)
        # Unicode case fold
        x2("(?i)\u1ffc", "\u2126\u1fbe", 0, 2)
        x2("(?i)\u1ffc", "\u1ff3", 0, 1)
        x2("(?i)\u0390", "\u03b9\u0308\u0301", 0, 3)
        x2("(?i)\u03b9\u0308\u0301", "\u0390", 0, 1)
        x2("(?i)ff", "\ufb00", 0, 1)
        x2("(?i)\ufb01", "fi", 0, 2)
        x2("(?i)\u0149\u0149", "\u0149\u0149", 0, 2)
        x2("(?i)(?<=\u0149)a", "\u02bcna", 2, 3)    # with look-behind
        # Other Unicode tests
        x2("\\x{25771}", "\U00025771", 0, 1)
    x2("[0-9-a]+", " 0123456789-a ", 1, 13)     # same as [0-9\-a]
    x2("[0-9-\\s]+", " 0123456789-a ", 0, 12)   # same as [0-9\-\s]
    n("[0-9-a]", "", syn=onigmo.ONIG_SYNTAX_GREP, err=onigmo.ONIGERR_UNMATCHED_RANGE_SPECIFIER_IN_CHAR_CLASS)
    x2("[0-9-あ\\\\/\u0001]+", " 0123456789-あ\\/\u0001 ", 1, 16)
    x2("[a-b-]+", "ab-", 0, 3)
    x2("[a-b-&&-]+", "ab-", 2, 3)
    x2("(?i)[a[b-あ]]+", "abあ", 0, 3)
    if is_unicode_encoding(onig_encoding):
        x2("(?i)[\\d[:^graph:]]+", "0あ", 0, 1)
    x2("(?ia)[\\d[:^print:]]+", "0あ", 0, 2)
    x2("(?i:a) B", "a B", 0, 3);
    x2("(?i:a )B", "a B", 0, 3);
    x2("B (?i:a)", "B a", 0, 3);
    x2("B(?i: a)", "B a", 0, 3);
    if is_unicode_encoding(onig_encoding):
        x2("(?a)[\\p{Space}\\d]", "\u00a0", 0, 1)
        x2("(?a)[\\d\\p{Space}]", "\u00a0", 0, 1)
        n("(?a)[^\\p{Space}\\d]", "\u00a0")
        n("(?a)[^\\d\\p{Space}]", "\u00a0")
        x2("(?d)[[:space:]\\d]", "\u00a0", 0, 1)
        n("(?d)[^\\d[:space:]]", "\u00a0")
    n("x.*?\\Z$", "x\ny")
    n("x.*?\\Z$", "x\r\ny")
    x2("x.*?\\Z$", "x\n", 0, 1)
    x2("x.*?\\Z$", "x\r\n", 0, 2)   # \Z will match between \r and \n, if
                                    # ONIG_OPTION_NEWLINE_CRLF isn't specified.
    x2("(?<=fo).*", "foo", 2, 3)        # Issue #15
    x2("(?m)(?<=fo).*", "foo", 2, 3)    # Issue #15
    x2("(?m)(?<=fo).+", "foo", 2, 3)    # Issue #15
    x2("\\n?\\z", "hello", 5, 5)
    x2("\\z", "hello", 5, 5)
    x2("\\n?\\z", "こんにちは", 5, 5)
    x2("\\z", "こんにちは", 5, 5)
    x2("()" * 32767, "", 0, 0)      # Issue #24
    n("()" * 32768, "", err=onigmo.ONIGERR_TOO_MANY_CAPTURE_GROUPS)
    x2("\\h+ \\H+", " 0123456789aBcDeF gh", 1, 20)
    x2("[\\h]+ [\\H]+", " 0123456789aBcDeF gh", 1, 20)
    x2("\\A(|.|(?:(.)\\g<1>\\k<2+0>))\\z", "reer", 0, 4)
    x2("\\A(?<a>|.|(?:(?<b>.)\\g<a>\\k<b+0>))\\z", "reer", 0, 4)
    x2("(?i)\\A(|.|(?:(.)\\g<1>\\k<2+0>))\\z", "reER", 0, 4)
    x2("(?i)\\A(?<a>|.|(?:(?<b>.)\\g<a>\\k<b+0>))\\z", "REer", 0, 4)
    x2(''' # Extended pattern
      (?<element> \g<stag> \g<content>* \g<etag> ){0}
      (?<stag> < \g<name> \s* > ){0}
      (?<name> [a-zA-Z_:]+ ){0}
      (?<content> [^<&]+ (\g<element> | [^<&]+)* ){0}
      (?<etag> </ \k<name+1> >){0}
      \g<element>''',
      "<foo>f<bar>bbb</bar>f</foo>", 0, 27, opt=onigmo.ONIG_OPTION_EXTEND)
    x2("(.)(?<a>a)(?<a>b)\\k<a>", "xaba", 0, 4)
    x2("\\p{Print}+", "\n a", 1, 3)
    x2("\\p{Graph}+", "\n a", 2, 3)
    n("a(?!b)", "ab");
    x2("(?:(.)\\1)*", "a" * 300, 0, 300)
    x2("\\cA\\C-B\\a[\\b]\\t\\n\\v\\f\\r\\e\\c?", "\x01\x02\x07\x08\x09\x0a\x0b\x0c\x0d\x1b\x7f", 0, 11)
    x2("(?<=(?:[a-z]|\\w){3})x", "ab1x", 3, 4)  # repeat inside look-behind
    x2("(?<n>(a|b\\g<n>c){3,5}?)", "baaaaca", 1, 4)
    x2("\\p{WoRd}", "a", 0, 1)  # property name is not case sensitive
    n("[[:WoRd:]]", "a", err=onigmo.ONIGERR_INVALID_POSIX_BRACKET_TYPE)   # POSIX bracket name is case sensitive
    n("(\\2)(\\1)", "")     # Issue #65
    n("(0?0|(?(1)||)|(?(1)||))?", "", err=onigmo.ONIGERR_INVALID_CONDITION_PATTERN) # Ruby Bug#12418
    n("[\\40000000000", "", err=onigmo.ONIGERR_TOO_BIG_NUMBER)  # Ruby Bug#12420
    n("[\\600000000000\n", "", err=onigmo.ONIGERR_TOO_BIG_NUMBER)   # Ruby Bug#12423
    n("[]", "", err=onigmo.ONIGERR_EMPTY_CHAR_CLASS)
    n("[c-a]", "", err=onigmo.ONIGERR_EMPTY_RANGE_IN_CHAR_CLASS)
    x2("[[:ab:\\x{30}]]+", ":ab0x", 0, 4)
    x2("[[:x\\]:]+", "[x:]", 0, 4)
    x2("[!--x]+", "!-x", 0, 3)
    x2(" ]", " ]", 0, 2)    # warning: ']' without escape
    n("\\x{FFFFFFFF}", "", err=onigmo.ONIGERR_TOO_BIG_WIDE_CHAR_VALUE);
    n("\\x{100000000}", "", err=onigmo.ONIGERR_TOO_LONG_WIDE_CHAR_VALUE);
    x2("\\u0026", "\u0026", 0, 1)
    x2("[\\u0024-\\u0027]", "\u0026", 0, 1)
    n("\\u026x", "", err=onigmo.ONIGERR_TOO_SHORT_DIGITS)
    n("()(?\\!(?'a')\\1)", "", err=onigmo.ONIGERR_UNDEFINED_GROUP_OPTION)
    x2("\\i", "i", 0, 1)    # unknown escape warning
    n("\\((", "", err=onigmo.ONIGERR_END_PATTERN_WITH_UNMATCHED_PARENTHESIS)
    n("(|", "", err=onigmo.ONIGERR_END_PATTERN_WITH_UNMATCHED_PARENTHESIS)
    x2("%{(.*?)}", "%{HOSTNAME}", 0, 11)
    if not is_ascii_incompatible_encoding(onig_encoding):
        n(b"'/g\\\xff\xff\xff\xff&))", "", err=onigmo.ONIGERR_UNMATCHED_CLOSE_PARENTHESIS)
        n(b"\\\xff0", "")
    if onig_encoding == onigmo.ONIG_ENCODING_UTF8:
        n(b"[0-0-\xe2  ", "", err=onigmo.ONIGERR_PREMATURE_END_OF_CHAR_CLASS)
    n("\\p{foobarbaz}", "", err=onigmo.ONIGERR_INVALID_CHAR_PROPERTY_NAME)
    n("\\p{あ}", "", err=onigmo.ONIGERR_INVALID_CHAR_PROPERTY_NAME)
    if is_unicode_encoding(onig_encoding):
        n("\\p{\U00025771}", "", err=onigmo.ONIGERR_INVALID_CHAR_PROPERTY_NAME)
    if onig_encoding == onigmo.ONIG_ENCODING_UTF8:
        x2("[\\xce\\xb1\\xce\\xb2]", "β", 0, 1)
    elif onig_encoding == onigmo.ONIG_ENCODING_SJIS or \
            onig_encoding == onigmo.ONIG_ENCODING_CP932:
        n("[\\x84A]", "", err=onigmo.ONIGERR_TOO_SHORT_MULTI_BYTE_STRING)
    elif onig_encoding == onigmo.ONIG_ENCODING_EUC_JP:
        n("[\\xAAA]", "", err=onigmo.ONIGERR_TOO_SHORT_MULTI_BYTE_STRING)
    elif is_ascii_incompatible_encoding(onig_encoding):
        n("[\\x420]", "", err=onigmo.ONIGERR_TOO_SHORT_MULTI_BYTE_STRING)
    x2("(?:a?)*", "aa", 0, 2)   # tests for reducing nested quantifiers
    x2("(?:a?)*?", "aa", 0, 0)
    x2("(?:a*)??", "aa", 0, 0)
    x2("(?:a+?)*", "aa", 0, 1)
    x2("(?:a*){2,3}", "aaa", 0, 3)
    n("(?:a+){2,3}", "a")
    x2("a{", "a{", 0, 2)        # invalid interval is allowed
    n("a{100001}", "", err=onigmo.ONIGERR_TOO_BIG_NUMBER_FOR_REPEAT_RANGE)
    n("a{0,100001}", "", err=onigmo.ONIGERR_TOO_BIG_NUMBER_FOR_REPEAT_RANGE)
    n("a{5,1}", "", err=onigmo.ONIGERR_UPPER_SMALLER_THAN_LOWER_IN_REPEAT_RANGE)
    x2("abc{1}", "abcc", 0, 3)
    x3("\\(((?:[^(]|\\g<0>)*)\\)", "(abc)(abc)", 1, 4, 1)   # Issue #48
    x3("\\(((?:[^(]|\\g<0>)*)\\)", "((abc)(abc))", 1, 11, 1)
    x3("\\(((?:[^(]|(\\g<0>))*)\\)", "((abc)(abc))", 6, 11, 2)

    # ONIG_OPTION_FIND_LONGEST option
    x2("foo|foobar", "foobar", 0, 3)
    x2("foo|foobar", "foobar", 0, 6, opt=onigmo.ONIG_OPTION_FIND_LONGEST)
    x2("a*", "aa aaa aaaa aaaaa ", 12, 17, opt=onigmo.ONIG_OPTION_FIND_LONGEST)

    # ONIG_OPTION_FIND_NOT_EMPTY option
    x2("\w*", " a", 0, 0)
    x2("\w*", " a", 1, 2, opt=onigmo.ONIG_OPTION_FIND_NOT_EMPTY)

    # ONIG_OPTION_DONT_CAPTURE_GROUP option
    x2("(ab|cd)*", "cdab", 0, 4, opt=onigmo.ONIG_OPTION_DONT_CAPTURE_GROUP)
    n("(ab|cd)*\\1", "", opt=onigmo.ONIG_OPTION_DONT_CAPTURE_GROUP, err=onigmo.ONIGERR_INVALID_BACKREF)

    # character classes (tests for character class optimization)
    x2("[@][a]", "@a", 0, 2);
    x2(".*[a][b][c][d][e]", "abcde", 0, 5);
    x2("(?i)[A\\x{41}]", "a", 0, 1);
    x2("[abA]", "a", 0, 1);
    x2("[[ab]&&[ac]]+", "aaa", 0, 3);
    x2("[[ab]&&[^b]]+", "aaa", 0, 3);
    x2("[[^b]&&[ab]]+", "aaa", 0, 3);
    x2("[[あい]&&[あう]]+", "あああ", 0, 3);
    x2("[[あい]&&[^い]]+", "あああ", 0, 3);
    x2("[[^い]&&[あい]]+", "あああ", 0, 3);

    # possessive quantifiers
    n("a?+a", "a")
    n("a*+a", "aaaa")
    n("a++a", "aaaa")
    x2("a{2,3}+a", "aaa", 0, 3) # Not a possessive quantifier in Ruby,
                                # same as "(?:a{2,3})+a"
    n("a{2,3}+a", "aaa", syn=onigmo.ONIG_SYNTAX_PERL)

    # automatic possessification
    x2("\\w+\\W", "abc#", 0, 4)
    x2("[a-c]+\\W", "abc#", 0, 4)
    x2("[a-c#]+\\W", "abc#", 0, 4)
    x2("[^a-c]+\\W", "def#", 0, 4)
    x2("(?a)[^a-c]+\\W", "def#", 0, 4)
    x2("a+\\w", "aaaa", 0, 4)
    x2("#+\\w", "###a", 0, 4)
    x2("(?a)a+\\w", "aaaa", 0, 4)
    x2("(?a)あ+\\w", "あああa", 0, 4)
    x2("[a-c]+[d-f]", "abcd", 0, 4)
    x2("[^d-f]+[d-f]", "abcd", 0, 4)
    x2("[a-cあ]+[d-f]", "abcd", 0, 4)

    # linebreak
    x2("\\R", "\n", 0, 1)
    x2("\\R", "\r", 0, 1)
    x2("\\R{3}", "\r\r\n\n", 0, 4)

    if (is_unicode_encoding(onig_encoding)):
        x2("\\R", "\u0085", 0, 1)
        x2("\\R", "\u2028", 0, 1)
        x2("\\R", "\u2029", 0, 1)

    # extended grapheme cluster
    x2("\\X{5}", "あいab\n", 0, 5)
    x2("\\X", "\n", 0, 1)
    x2("\\X", "\r", 0, 1)
    x2("\\X{3}", "\r\r\n\n", 0, 4)
    if is_unicode_encoding(onig_encoding):
        x2("\\X", "\u306F\u309A\n", 0, 2)
        x2("\\A\\X\\z", "\u0020\u200d", 0, 2)
        x2("\\A\\X\\z", "\u0600\u0600", 0, 2)
        x2("\\A\\X\\z", "\u0600\u0020", 0, 2)
        x2("\\A\\X\\z", "\u261d\U0001F3FB", 0, 2)
        x2("\\A\\X\\z", "\U0001f600", 0, 1)
        x2("\\A\\X\\z", "\u0020\u0308", 0, 2)
        x2("\\A\\X\\X\\z", "\u000a\u0308", 0, 2)
        x2("\\A\\X\\X\\z", "\u000d\u0308", 0, 2)
        x2("\\A\\X\\z", "\U0001F477\U0001F3FF\u200D\u2640\uFE0F", 0, 5)
        x2("\\A\\X\\z", "\U0001F468\u200D\U0001F393", 0, 3)
        x2("\\A\\X\\z", "\U0001F46F\u200D\u2642\uFE0F", 0, 4)
        x2("\\A\\X\\z", "\U0001F469\u200d\u2764\ufe0f\u200d\U0001F469", 0, 6)

    # keep
    x2("ab\\Kcd", "abcd", 2, 4)
    x2("ab\\Kc(\\Kd|z)", "abcd", 3, 4)
    x2("ab\\Kc(\\Kz|d)", "abcd", 2, 4)
    x2("(a\\K)*", "aaab", 3, 3)
    x3("(a\\K)*", "aaab", 2, 3, 1)
#    x2("a\\K?a", "aa", 0, 2)        # error: differ from perl
    x2("ab(?=c\Kd)", "abcd", 2, 2)          # This behaviour is currently not well defined. (see: perlre)
    x2("(?<=a\\Kb|aa)cd", "abcd", 1, 4)     # This behaviour is currently not well defined. (see: perlre)
    x2("(?<=ab|a\\Ka)cd", "abcd", 2, 4)     # This behaviour is currently not well defined. (see: perlre)

    # named group and subroutine call
    x2("(?<name_2>ab)(?&name_2)", "abab", 0, 4, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(?<name_2>ab)(?1)", "abab", 0, 4, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(?'n'|\\((?&n)\\))+$", "()(())", 0, 6, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(a|x(?-1)x)", "xax", 0, 3, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(a|(x(?-2)x))", "xax", 0, 3, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("a|x(?0)x", "xax", 0, 3, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("a|x(?R)x", "xax", 0, 3, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(a|x\g<0>x)", "xax", 0, 3);
    x2("(a|x\g'0'x)", "xax", 0, 3);
    x2("(?-i:(?+1))(?i:(a)){0}", "A", 0, 1, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(?-i:\g<+1>)(?i:(a)){0}", "A", 0, 1);
    x2("(?-i:\g'+1')(?i:(a)){0}", "A", 0, 1);
    n("(.(?=\\g<1>))", "", err=onigmo.ONIGERR_NEVER_ENDING_RECURSION)
    n("(a)(?<n>b)\\g<1>\\g<n>", "abab", err=onigmo.ONIGERR_NUMBERED_BACKREF_OR_CALL_NOT_ALLOWED)
    x2("(a)(?<n>b)(?1)(?&n)", "abab", 0, 4, syn=onigmo.ONIG_SYNTAX_PERL)
    x2("((?<v>)a)|b\\g<0>b", "bbabb", 0, 5)
    x2("((?<v>)a)|b(?0)b", "bbabb", 0, 5, syn=onigmo.ONIG_SYNTAX_PERL)
    x2("((?<v>)a|b(?1)b)", "bbabb", 0, 5, syn=onigmo.ONIG_SYNTAX_PERL)
    x2("((?<v>a|b(?&v)b))", "bbabb", 0, 5, syn=onigmo.ONIG_SYNTAX_PERL)
    n("(?<", "", err=onigmo.ONIGERR_END_PATTERN_WITH_UNMATCHED_PARENTHESIS)
    n("(?<>)", "", err=onigmo.ONIGERR_EMPTY_GROUP_NAME)
    n("(?<.>)", "", err=onigmo.ONIGERR_INVALID_CHAR_IN_GROUP_NAME)
    n("\\g<1->", "", err=onigmo.ONIGERR_INVALID_CHAR_IN_GROUP_NAME)
    n("\\k<1/>", "", err=onigmo.ONIGERR_INVALID_GROUP_NAME)
    n("\\k<1-1/>", "", err=onigmo.ONIGERR_INVALID_GROUP_NAME)
    n("\\k<a/>", "", err=onigmo.ONIGERR_INVALID_CHAR_IN_GROUP_NAME)

    # character set modifiers
    x2("(?u)\\w+", "あa#", 0, 2);
    x2("(?a)\\w+", "あa#", 1, 2);
    x2("(?u)\\W+", "あa#", 2, 3);
    x2("(?a)\\W+", "あa#", 0, 1);

    x2("(?a)\\b", "あa", 1, 1);
    x2("(?a)\\w\\b", "aあ", 0, 1);
    x2("(?a)\\B", "a ああ ", 2, 2);

    x2("(?u)\\B", "あ ", 2, 2);
    x2("(?a)\\B", "あ ", 0, 0);
    x2("(?a)\\B", "aあ ", 2, 2);

    x2("(?a)a\\b", " a", 1, 2)
    x2("(?u)a\\b", " a", 1, 2)
    n("(?a)a\\B", " a")
    n("(?a)あ\\b", " あ")
    x2("(?u)あ\\b", " あ", 1, 2)
    x2("(?a)あ\\B", " あ", 1, 2)
    n("(?u)あ\\B", " あ")

    x2("(?a)\\p{Alpha}\\P{Alpha}", "a。", 0, 2);
    x2("(?u)\\p{Alpha}\\P{Alpha}", "a。", 0, 2);
    x2("(?a)[[:word:]]+", "aあ", 0, 1);
    x2("(?a)[[:^word:]]+", "aあ", 1, 2);
    x2("(?u)[[:word:]]+", "aあ", 0, 2);
    n("(?u)[[:^word:]]+", "aあ");

    x2("(?iu)\\p{lower}\\p{upper}", "Ab", 0, 2);
    x2("(?ia)\\p{lower}\\p{upper}", "Ab", 0, 2);
    x2("(?iu)[[:lower:]][[:upper:]]", "Ab", 0, 2);
    x2("(?ia)[[:lower:]][[:upper:]]", "Ab", 0, 2);

    if is_unicode_encoding(onig_encoding):
        n("(?ia)\\w+", "\u212a\u017f");      # KELVIN SIGN, LATIN SMALL LETTER LONG S
        n("(?ia)[\\w]+", "\u212a\u017f");
        n("(?ia)[^\\W]+", "\u212a\u017f");
        x2("(?ia)[^\\W]+", "ks", 0, 2);
        n("(?iu)\\p{ASCII}", "\u212a");
        n("(?iu)\\P{ASCII}", "s");
        n("(?iu)[\\p{ASCII}]", "\u212a");
        n("(?iu)[\\P{ASCII}]", "s");
        n("(?ia)\\p{ASCII}", "\u212a");
        n("(?ia)\\P{ASCII}", "s");
        n("(?ia)[\\p{ASCII}]", "\u212a");
        n("(?ia)[\\P{ASCII}]", "s");
        x2("(?iu)[s]+", "Ss\u017f ", 0, 3);
        x2("(?ia)[s]+", "Ss\u017f ", 0, 3);
        x2("(?iu)[^s]+", "Ss\u017f ", 3, 4);
        x2("(?ia)[^s]+", "Ss\u017f ", 3, 4);
        x2("(?iu)[[:lower:]]", "\u017f", 0, 1);
        n("(?ia)[[:lower:]]", "\u017f");
        x2("(?u)[[:upper:]]", "\u212a", 0, 1);
        n("(?a)[[:upper:]]", "\u212a");

    # Grep syntax
    # \+, \?, \|, \{n,m\}
    x2("a\\+", "aa", 0, 2, syn=onigmo.ONIG_SYNTAX_GREP)
    n("a\\+", "b", syn=onigmo.ONIG_SYNTAX_GREP)
    x2("a\\?", "", 0, 0, syn=onigmo.ONIG_SYNTAX_GREP)
    x2("a\\?", "a", 0, 1, syn=onigmo.ONIG_SYNTAX_GREP)
    x2("ab\\|cd", "cd", 0, 2, syn=onigmo.ONIG_SYNTAX_GREP)
    x2("a\\{1,2\\}", "aaa", 0, 2, syn=onigmo.ONIG_SYNTAX_GREP)
    x2("a\\{2\\}", "aaa", 0, 2, syn=onigmo.ONIG_SYNTAX_GREP)
    n("a\\{|", "", syn=onigmo.ONIG_SYNTAX_GREP, err=onigmo.ONIGERR_END_PATTERN_AT_LEFT_BRACE)
    # \< and \>
    x2("\\<abc\\>", " abc ", 1, 4, syn=onigmo.ONIG_SYNTAX_GREP)
    n("\\<abc\\>", "zabc ", syn=onigmo.ONIG_SYNTAX_GREP)
    n("\\<abc\\>", " abcd", syn=onigmo.ONIG_SYNTAX_GREP)
    n("\\<abc\\>", "あabcい", syn=onigmo.ONIG_SYNTAX_GREP)
    x2("\\<abc\\>", "あabcい", 1, 4, syn=onigmo.ONIG_SYNTAX_GREP, opt=onigmo.ONIG_OPTION_ASCII_RANGE)
    n("\\<abc\\>", "zabcい", syn=onigmo.ONIG_SYNTAX_GREP, opt=onigmo.ONIG_OPTION_ASCII_RANGE)
    n("\\<abc\\>", "あabcd", syn=onigmo.ONIG_SYNTAX_GREP, opt=onigmo.ONIG_OPTION_ASCII_RANGE)
    # others
    n("[^a]", "\n", syn=onigmo.ONIG_SYNTAX_GREP)
    x2("*", "*", 0, 1, syn=onigmo.ONIG_SYNTAX_GREP)
    #x2("\\{1\\}", "{1}", 0, 3, syn.onigmo.ONIG_SYNTAX_GREP)    # fails
    n("*", "", err=onigmo.ONIGERR_TARGET_OF_REPEAT_OPERATOR_NOT_SPECIFIED)
    n("{1}", "", err=onigmo.ONIGERR_TARGET_OF_REPEAT_OPERATOR_NOT_SPECIFIED)

    # \g{} backref
    x2("((?<name1>\\d)|(?<name2>\\w))(\\g{name1}|\\g{name2})", "ff", 0, 2, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(?:(?<x>)|(?<x>efg))\\g{x}", "", 0, 0, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(?:(?<x>abc)|(?<x>efg))\\g{x}", "efgabcabc", 3, 9, syn=onigmo.ONIG_SYNTAX_PERL);
    n("(?:(?<x>abc)|(?<x>efg))\\g{x}", "abcefg", syn=onigmo.ONIG_SYNTAX_PERL);
    x2("((.*)a\\g{2}f)", "bacbabf", 3, 7, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(.*)a\\g{1}f", "baczzzzzz\nbazz\nzzzzbabf", 19, 23, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("((.*)a\\g{-1}f)", "bacbabf", 3, 7, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(.*)a\\g{-1}f", "baczzzzzz\nbazz\nzzzzbabf", 19, 23, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(あ*)(い*)\\g{-2}\\g{-1}", "あああいいあああいい", 0, 10, syn=onigmo.ONIG_SYNTAX_PERL);

    # Python/PCRE compatible named group
    x2("(?P<name_2>ab)(?P>name_2)", "abab", 0, 4, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("(?P<n>|\\((?P>n)\\))+$", "()(())", 0, 6, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("((?P<name1>\\d)|(?P<name2>\\w))((?P=name1)|(?P=name2))", "ff", 0, 2, syn=onigmo.ONIG_SYNTAX_PERL);
    n("(?P", "", syn=onigmo.ONIG_SYNTAX_PERL, err=onigmo.ONIGERR_UNDEFINED_GROUP_OPTION)
    n("(?PX", "", syn=onigmo.ONIG_SYNTAX_PERL, err=onigmo.ONIGERR_UNDEFINED_GROUP_OPTION)

    # Fullwidth Alphabet
    n("ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ", "ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ");
    x2("(?i)ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ", "ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ", 0, 26);
    x2("(?i)ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ", "ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ", 0, 26);
    x2("(?i)ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ", "ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ", 0, 26);
    x2("(?i)ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ", "ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ", 0, 26);

    # Greek
    n("αβγδεζηθικλμνξοπρστυφχψω", "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ");
    x2("(?i)αβγδεζηθικλμνξοπρστυφχψω", "αβγδεζηθικλμνξοπρστυφχψω", 0, 24);
    x2("(?i)αβγδεζηθικλμνξοπρστυφχψω", "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ", 0, 24);
    x2("(?i)ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ", "αβγδεζηθικλμνξοπρστυφχψω", 0, 24);
    x2("(?i)ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ", "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ", 0, 24);

    # Cyrillic
    n("абвгдеёжзийклмнопрстуфхцчшщъыьэюя", "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
    x2("(?i)абвгдеёжзийклмнопрстуфхцчшщъыьэюя", "абвгдеёжзийклмнопрстуфхцчшщъыьэюя", 0, 33);
    x2("(?i)абвгдеёжзийклмнопрстуфхцчшщъыьэюя", "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ", 0, 33);
    x2("(?i)АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ", "абвгдеёжзийклмнопрстуфхцчшщъыьэюя", 0, 33);
    x2("(?i)АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ", "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ", 0, 33);

    # multiple name definition
    x2("(?<a>a)(?<a>b)\\k<a>", "aba", 0, 3)
    x2("(?<a>a)(?<a>b)\\k<a>", "abb", 0, 3)
    x2("(?<a>a)(?<a>b)\\g{a}", "aba", 0, 3, syn=onigmo.ONIG_SYNTAX_PERL)
    n("(?<a>a)(?<a>b)\\g{a}", "abb", syn=onigmo.ONIG_SYNTAX_PERL)
    n("(?<a>a)(?<a>b)\\g<a>", "aba", err=onigmo.ONIGERR_MULTIPLEX_DEFINITION_NAME_CALL)
    x2("(?<a>[ac])(?<a>b)(?&a)", "abc", 0, 3, syn=onigmo.ONIG_SYNTAX_PERL)
    n("(?<a>[ac])(?<a>b)(?&a)", "abb", syn=onigmo.ONIG_SYNTAX_PERL)
    x2("(?:(?<x>abc)|(?<x>efg))(?i:\\k<x>)", "abcefgEFG", 3, 9)
    x2("(?<x>a)(?<x>b)(?i:\\k<x>)+", "abAB", 0, 4)

    # branch reset
#    x3("(?|(c)|(?:(b)|(a)))", "a", 0, 1, 2)
#    x3("(?|(c)|(?|(b)|(a)))", "a", 0, 1, 1)

    # conditional expression
    x2("(?:(a)|(b))(?(1)cd)e", "acde", 0, 4)
    n("(?:(a)|(b))(?(1)cd)e", "ae")
    x2("(?:(a)|(b))(?(2)cd)e", "ae", 0, 2)
    n("(?:(a)|(b))(?(2)cd)e", "acde")
    x2("(?:(a)|(b))(?(1)c|d)", "ac", 0, 2)
    x2("(?:(a)|(b))(?(1)c|d)", "bd", 0, 2)
    n("(?:(a)|(b))(?(1)c|d)", "ad")
    n("(?:(a)|(b))(?(1)c|d)", "bc")
    x2("(?:(a)|(b))(?:(?(1)cd)e|fg)", "acde", 0, 4)
    x2("(?:(a)|(b))(?:(?(1)cd|x)e|fg)", "bxe", 0, 3)
    n("(?:(a)|(b))(?:(?(2)cd|x)e|fg)", "bxe")
    x2("(?:(?<x>a)|(?<y>b))(?:(?(<x>)cd|x)e|fg)", "bxe", 0, 3)
    n("(?:(?<x>a)|(?<y>b))(?:(?(<y>)cd|x)e|fg)", "bxe")
    x2("((?<=a))?(?(1)b|c)", "abc", 1, 2)
    x2("((?<=a))?(?(1)b|c)", "bc", 1, 2)
    x2("((?<x>x)|(?<y>y))(?(<x>)y|x)", "xy", 0, 2)
    x2("((?<x>x)|(?<y>y))(?(<x>)y|x)", "yx", 0, 2)
    n("((?<x>x)|(?<y>y))(?(<x>)y|x)", "xx")
    n("((?<x>x)|(?<y>y))(?(<x>)y|x)", "yy")
    n("(a)?(?<n>b)?(?(1)a)(?(<n>)b)", "aa", err=onigmo.ONIGERR_NUMBERED_BACKREF_OR_CALL_NOT_ALLOWED)
    x2("(a)?(?<n>b)?(?(1)a)(?(<n>)b)", "aa", 0, 2, syn=onigmo.ONIG_SYNTAX_PERL)
    n("()(?(2))", "", err=onigmo.ONIGERR_INVALID_BACKREF)       # Issue #65
    n("(?(700000))", "", err=onigmo.ONIGERR_INVALID_BACKREF)

    # Implicit-anchor optimization
    x2("(?m:.*abc)", "dddabdd\nddabc", 0, 13)   # optimized /(?m:.*abc)/ ==> /\A(?m:.*abc)/
    x2("(?m:.+abc)", "dddabdd\nddabc", 0, 13)   # optimized
    x2("(?-m:.*abc)", "dddabdd\nddabc", 8, 13)  # optimized /(?-m:.*abc)/ ==> /(?:^|\A)(?m:.*abc)/
    n("(?-m:.*ab[x-z])", "dddabdd\nddabc")      # optimized
    x2("(?-m:.*(?:abc|\\Gabc))", "dddabdd\nddabc", 8, 13)  # optimized
    x2("(?-m:.+abc)", "dddabdd\nddabc", 8, 13)  # optimized
    x2("(?-m:.*abc)", "dddabdd\nabc", 8, 11)    # optimized
    n("(?-m:.+abc)", "dddabdd\nabc")            # optimized
    x2("(?m:.*\\Z)", "dddabdd\nddabc", 0, 13)   # optimized /(?m:.*\Z)/ ==> /\A(?m:.*\Z)/
    x2("(?-m:.*\\Z)", "dddabdd\nddabc", 8, 13)  # optimized /(?-m:.*\Z)/ ==> /(?:^|\A)(?m:.*\Z)/
    x2("(.*)X\\1", "1234X2345", 1, 8)           # not optimized

    # Allow options in look-behind
    x2("(?<=(?i)ab)cd", "ABcd", 2, 4)
    x2("(?<=(?i:ab))cd", "ABcd", 2, 4)
    n("(?<=(?i)ab)cd", "ABCD")
    n("(?<=(?i:ab))cd", "ABCD")
    x2("(?<!(?i)ab)cd", "aacd", 2, 4)
    x2("(?<!(?i:ab))cd", "aacd", 2, 4)
    n("(?<!(?i)ab)cd", "ABcd")
    n("(?<!(?i:ab))cd", "ABcd")

    # Absent operator
    x2("<-(?~->)->", "<- ->->", 0, 5)
    x2("<-(?~->)->\n", "<-1->2<-3->\n", 6, 12)
    x2("<-(?~->)->.*<-(?~->)->", "<-1->2<-3->4<-5->", 0, 17)
    x2("<-(?~->)->.*?<-(?~->)->", "<-1->2<-3->4<-5->", 0, 11)
    x2("(?~abc)c", "abc", 0, 3)
    x2("(?~abc)bc", "abc", 0, 3)
    x2("(?~abc)abc", "abc", 0, 3)
    n("(?~)", " ")
    n("(?~)", "")
    n(" (?~)", "  ")
    n(" (?~)", " ")
    x2("(?~(?~))", "abc", 0, 3)
    x2("(?~a)", "", 0, 0)
    x2("(?~a)a", "a", 0, 1)
    x2("(?~a)", "x", 0, 1)
    x2("(?~a)a", "xa", 0, 2)
    x2("(?~.)", "", 0, 0)
    x2("(?~.)a", "a", 0, 1)
    x2("(?~.)", "x", 0, 0)
    x2("(?~.)a", "xa", 1, 2)
    x2("(?~abc)", "abc", 0, 2)
    x2("(?~b)", "abc", 0, 1)
    x2("(?~abc|b)", "abc", 0, 1)
    n("(?~|abc)", "abc")            # ???
    x2("(?~abc|)", "abc", 0, 1)     # ???
    x2("(?~abc|def)x", "abcx", 1, 4)
    x2("(?~abc|def)x", "defx", 1, 4)
    x2("^(?~\\S+)TEST", "TEST", 0, 4)

    # Perl syntax
    x2("\\Q()\\[a]\\E[b]", "()\\[a]b", 0, 7, syn=onigmo.ONIG_SYNTAX_PERL)
    x2("\\Q()\\[a]", "()\\[a]", 0, 6, syn=onigmo.ONIG_SYNTAX_PERL)  # no \E
    x2("(?a)(?d)\\w+", "あ", 0, 1, syn=onigmo.ONIG_SYNTAX_PERL) # For now (?d) == (?u)
    x2("(?a)(?l)\\w+", "あ", 0, 1, syn=onigmo.ONIG_SYNTAX_PERL) # For now (?l) == (?u)
    x2("(?a)(?^)\\w+", "あ", 0, 1, syn=onigmo.ONIG_SYNTAX_PERL)
    n("(?i)(?^)a", "A", syn=onigmo.ONIG_SYNTAX_PERL)
    n("(?m)(?^)a$", "a\nb", syn=onigmo.ONIG_SYNTAX_PERL)
    x2("(?s)(?^).*", "a\nb", 0, 1, syn=onigmo.ONIG_SYNTAX_PERL)
    x2("\\o{046}", "\046", 0, 1, syn=onigmo.ONIG_SYNTAX_PERL);
    x2("[\\o{044}-\\o{047}]", "\046", 0, 1, syn=onigmo.ONIG_SYNTAX_PERL);
    n("\\o{40000000000}", "", syn=onigmo.ONIG_SYNTAX_PERL, err=onigmo.ONIGERR_TOO_BIG_WIDE_CHAR_VALUE);
    n("\\o{100000000000}", "", syn=onigmo.ONIG_SYNTAX_PERL, err=onigmo.ONIGERR_TOO_LONG_WIDE_CHAR_VALUE);
    n("[\\o{40000000000}]", "", syn=onigmo.ONIG_SYNTAX_PERL, err=onigmo.ONIGERR_TOO_BIG_WIDE_CHAR_VALUE);
    n("[\\o{100000000000}]", "", syn=onigmo.ONIG_SYNTAX_PERL, err=onigmo.ONIGERR_TOO_LONG_WIDE_CHAR_VALUE);

    # Backward search
    x2("abc", "abcabc", 3, 6, searchtype=SearchType.BACKWARD)
    x2("あいう", "あいうあいう", 3, 6, searchtype=SearchType.BACKWARD)
    x2("(?i)abc", "ABCABC", 3, 6, searchtype=SearchType.BACKWARD)
    x2("(?i)ａｂｃ", "ＡＢＣＡＢＣ", 3, 6, searchtype=SearchType.BACKWARD)
    x2("[a-z]{3}$", "abcabc", 3, 6, searchtype=SearchType.BACKWARD)
    x2("[あ-ん]{3}$", "あいうあいう", 3, 6, searchtype=SearchType.BACKWARD)
    x2(".*[a-z]bc", "abcabc", 3, 6, searchtype=SearchType.BACKWARD) # Issue #69
    x2(".+[a-z]bc", "abcabc", 2, 6, searchtype=SearchType.BACKWARD) # Issue #69
    x2(".{1,3}[a-z]bc", "abcabc", 2, 6, searchtype=SearchType.BACKWARD)

    # onig_match()
    x2("abc", "abcabc", 0, 3, searchtype=SearchType.MATCH)
    n("abc", " abcabc", searchtype=SearchType.MATCH)

    # onig_search_gpos()
    n("\\Gabc", "123abcdef", gpos=2)
    x2("\\Gabc", "123abcdef", 3, 6, gpos=3)
    x2("\\Gabc", "123abcdef", 3, 6, startpos=3)
    n("\\Gabc", "123abcdef", gpos=0, startpos=3)
    x2("abc\\G", "abc", 0, 3, searchtype=SearchType.BACKWARD)
    n("abc\\G", "abc ", searchtype=SearchType.BACKWARD)
    x2("abc\\G", "abc ", 0, 3, searchtype=SearchType.BACKWARD, endpos=3)
    x2("abc\\G", "abc ", 0, 3, searchtype=SearchType.BACKWARD, gpos=3)

    # stack size
    stack_size = onigmo.onig_get_match_stack_limit_size()
    print("Default stack size:", stack_size)
    onigmo.onig_set_match_stack_limit_size(1000)
    print("New stack size:", onigmo.onig_get_match_stack_limit_size())
    # These patterns need deep stack.
    n("^a*$", "a" * 200 + "b")
    n("^a*$", "a" * 2000 + "b", execerr=onigmo.ONIGERR_MATCH_STACK_LIMIT_OVER)
    onigmo.onig_set_match_stack_limit_size(0)

    # parse depth
    parse_depth = onigmo.onig_get_parse_depth_limit()
    print("Default parse depth:", parse_depth)
    onigmo.onig_set_parse_depth_limit(1000)
    print("New parse depth:", onigmo.onig_get_parse_depth_limit())
    # These patterns need deep parse stack.
    x2("(" * 200 + "a" + ")" * 200, "a", 0, 1)
    n("(" * 2000 + "a" + ")" * 2000, "a", err=onigmo.ONIGERR_PARSE_DEPTH_LIMIT_OVER)
    onigmo.onig_set_match_stack_limit_size(0)

    # syntax functions
    onigmo.onig_set_syntax_op(syntax_default,
        onigmo.onig_get_syntax_op(onigmo.ONIG_SYNTAX_DEFAULT))
    onigmo.onig_set_syntax_op2(syntax_default,
        onigmo.onig_get_syntax_op2(onigmo.ONIG_SYNTAX_DEFAULT))
    onigmo.onig_set_syntax_behavior(syntax_default,
        onigmo.onig_get_syntax_behavior(onigmo.ONIG_SYNTAX_DEFAULT))
    onigmo.onig_set_default_syntax(None)


    print("\nEncoding:", get_encoding_name(onig_encoding))
    print("RESULT   SUCC: %d,  FAIL: %d,  ERROR: %d      (by Onigmo %s)" % (
          nsucc, nfail, nerror, onigmo.onig_version()))

    onigmo.onig_end()

    if (nfail == 0 and nerror == 0):
        exit(0)
    else:
        exit(-1)

if __name__ == '__main__':
    main()

