/*
 * Copyright (c) 2014 DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * lib/file/templates.c.h is automatically generated from lib/file/_templates.h
 * with command:
 *   picotemplate.pl --conf=misc/picotemplate-conf.pl lib/file/_templates.c.h
 */

static int cmpstrptr(const void *_x, const void *_y)
{
    const char *x = *(const char **)_x;
    const char *y = *(const char **)_y;
    return strcmp(x, y);
}

static h2o_buffer_t *build_dir_listing_html(h2o_mem_pool_t *pool, h2o_iovec_t path_normalized, DIR *dp)
{
    H2O_VECTOR(char *)files = {};

    { /* build list of files */
        struct dirent dent, *dentp;
        int ret;
        while ((ret = readdir_r(dp, &dent, &dentp)) == 0 && dentp != NULL) {
            if (strcmp(dent.d_name, ".") == 0 || strcmp(dent.d_name, "..") == 0)
                continue;
            h2o_vector_push_back(pool, &files, h2o_strdup(pool, dent.d_name, SIZE_MAX).base);
        }
        qsort(files.entries, files.size, sizeof(files.entries[0]), cmpstrptr);
    }

    h2o_buffer_t *_;
    h2o_iovec_t path_normalized_escaped = h2o_htmlescape(pool, path_normalized.base, path_normalized.len);

    h2o_buffer_init(&_, &h2o_socket_buffer_prototype);

    {
        h2o_iovec_t _s = (h2o_iovec_init(H2O_STRLIT("<!DOCTYPE html>\n<TITLE>Index of ")));
        if (_s.len != 0 && _s.base[_s.len - 1] == '\n')
            --_s.len;
        h2o_buffer_reserve(&_, _s.len);
        memcpy(_->bytes + _->size, _s.base, _s.len);
        _->size += _s.len;
    }
    {
        h2o_iovec_t _s = (path_normalized_escaped);
        if (_s.len != 0 && _s.base[_s.len - 1] == '\n')
            --_s.len;
        h2o_buffer_reserve(&_, _s.len);
        memcpy(_->bytes + _->size, _s.base, _s.len);
        _->size += _s.len;
    }
    {
        h2o_iovec_t _s = (h2o_iovec_init(H2O_STRLIT("</TITLE>\n<H2>Index of ")));
        if (_s.len != 0 && _s.base[_s.len - 1] == '\n')
            --_s.len;
        h2o_buffer_reserve(&_, _s.len);
        memcpy(_->bytes + _->size, _s.base, _s.len);
        _->size += _s.len;
    }
    {
        h2o_iovec_t _s = (path_normalized_escaped);
        if (_s.len != 0 && _s.base[_s.len - 1] == '\n')
            --_s.len;
        h2o_buffer_reserve(&_, _s.len);
        memcpy(_->bytes + _->size, _s.base, _s.len);
        _->size += _s.len;
    }
    {
        h2o_iovec_t _s = (h2o_iovec_init(H2O_STRLIT("</H2>\n<UL>\n<LI><A HREF=\"..\">Parent Directory</A>\n")));
        if (_s.len != 0 && _s.base[_s.len - 1] == '\n')
            --_s.len;
        h2o_buffer_reserve(&_, _s.len);
        memcpy(_->bytes + _->size, _s.base, _s.len);
        _->size += _s.len;
    }

    size_t i;
    for (i = 0; i != files.size; ++i) {
        h2o_iovec_t link_escaped = h2o_uri_escape(pool, files.entries[i], strlen(files.entries[i]), NULL);
        link_escaped = h2o_htmlescape(pool, link_escaped.base, link_escaped.len);
        h2o_iovec_t label_escaped = h2o_htmlescape(pool, files.entries[i], strlen(files.entries[i]));
        {
            h2o_iovec_t _s = (h2o_iovec_init(H2O_STRLIT("<LI><A HREF=\"")));
            if (_s.len != 0 && _s.base[_s.len - 1] == '\n')
                --_s.len;
            h2o_buffer_reserve(&_, _s.len);
            memcpy(_->bytes + _->size, _s.base, _s.len);
            _->size += _s.len;
        }
        {
            h2o_iovec_t _s = (link_escaped);
            if (_s.len != 0 && _s.base[_s.len - 1] == '\n')
                --_s.len;
            h2o_buffer_reserve(&_, _s.len);
            memcpy(_->bytes + _->size, _s.base, _s.len);
            _->size += _s.len;
        }
        {
            h2o_iovec_t _s = (h2o_iovec_init(H2O_STRLIT("\">")));
            if (_s.len != 0 && _s.base[_s.len - 1] == '\n')
                --_s.len;
            h2o_buffer_reserve(&_, _s.len);
            memcpy(_->bytes + _->size, _s.base, _s.len);
            _->size += _s.len;
        }
        {
            h2o_iovec_t _s = (label_escaped);
            if (_s.len != 0 && _s.base[_s.len - 1] == '\n')
                --_s.len;
            h2o_buffer_reserve(&_, _s.len);
            memcpy(_->bytes + _->size, _s.base, _s.len);
            _->size += _s.len;
        }
        {
            h2o_iovec_t _s = (h2o_iovec_init(H2O_STRLIT("</A>\n")));
            if (_s.len != 0 && _s.base[_s.len - 1] == '\n')
                --_s.len;
            h2o_buffer_reserve(&_, _s.len);
            memcpy(_->bytes + _->size, _s.base, _s.len);
            _->size += _s.len;
        }
    }

    return _;
}
