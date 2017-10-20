/*
 * apilist.c
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "mrdb.h"
#include "mrdberror.h"
#include "apilist.h"
#include <mruby/compile.h>
#include <mruby/irep.h>
#include <mruby/debug.h>

#define LINE_BUF_SIZE MAX_COMMAND_LINE

typedef struct source_file {
  char *path;
  uint16_t lineno;
  FILE *fp;
} source_file;

static void
source_file_free(mrb_state *mrb, source_file *file)
{
  if (file != NULL) {
    if (file->path != NULL) {
      mrb_free(mrb, file->path);
    }
    if (file->fp != NULL) {
      fclose(file->fp);
      file->fp = NULL;
    }
    mrb_free(mrb, file);
  }
}

static char*
build_path(mrb_state *mrb, const char *dir, const char *base)
{
  int len;
  char *path = NULL;

  len = strlen(base) + 1;

  if (strcmp(dir, ".")) {
    len += strlen(dir) + sizeof("/") - 1;
  }

  path = mrb_malloc(mrb, len);
  memset(path, 0, len);

  if (strcmp(dir, ".")) {
    strcat(path, dir);
    strcat(path, "/");
  }
  strcat(path, base);

  return path;
}

static char*
dirname(mrb_state *mrb, const char *path)
{
  size_t len;
  char *p, *dir;

  if (path == NULL) {
    return NULL;
  }

  p = strrchr(path, '/');
  len = p != NULL ? (size_t)(p - path) : strlen(path);

  dir = mrb_malloc(mrb, len + 1);
  strncpy(dir, path, len);
  dir[len] = '\0';

  return dir;
}

static source_file*
source_file_new(mrb_state *mrb, mrb_debug_context *dbg, char *filename)
{
  source_file *file = NULL;

  file = mrb_malloc(mrb, sizeof(source_file));

  memset(file, '\0', sizeof(source_file));
  file->fp = fopen(filename, "rb");

  if (file->fp == NULL) {
    source_file_free(mrb, file);
    return NULL;
  }

  file->lineno = 1;
  file->path = mrb_malloc(mrb, strlen(filename) + 1);
  strcpy(file->path, filename);
  return file;
}

static mrb_bool
remove_newlines(char *s, FILE *fp)
{
  int c;
  char *p;
  size_t len;

  if ((len = strlen(s)) == 0) {
    return FALSE;
  }

  p = s + len - 1;

  if (*p != '\r' && *p != '\n') {
    return FALSE;
  }

  if (*p == '\r') {
    /* peek the next character and skip '\n' */
    if ((c = fgetc(fp)) != '\n') {
      ungetc(c, fp);
    }
  }

  /* remove trailing newline characters */
  while (s <= p && (*p == '\r' || *p == '\n')) {
    *p-- = '\0';
  }

  return TRUE;
}

static void
show_lines(source_file *file, uint16_t line_min, uint16_t line_max)
{
  char buf[LINE_BUF_SIZE];
  int show_lineno = 1, found_newline = 0, is_printed = 0;

  if (file->fp == NULL) {
    return;
  }

  while (fgets(buf, sizeof(buf), file->fp) != NULL) {
    found_newline = remove_newlines(buf, file->fp);

    if (line_min <= file->lineno) {
      if (show_lineno) {
        printf("%-8d", file->lineno);
      }
      show_lineno = found_newline;
      printf(found_newline ? "%s\n" : "%s", buf);
      is_printed = 1;
    }

    if (found_newline) {
      if (line_max < ++file->lineno) {
        break;
      }
    }
  }

  if (is_printed && !found_newline) {
    printf("\n");
  }
}

char*
mrb_debug_get_source(mrb_state *mrb, mrdb_state *mrdb, const char *srcpath, const char *filename)
{
  int i;
  FILE *fp;
  const char *search_path[3];
  char *path = NULL;
  const char *srcname = strrchr(filename, '/');

  if (srcname) srcname++;
  else srcname = filename;

  search_path[0] = srcpath;
  search_path[1] = dirname(mrb, mrb_debug_get_filename(mrdb->dbg->irep, 0));
  search_path[2] = ".";

  for (i = 0; i < 3; i++) {
    if (search_path[i] == NULL) {
      continue;
    }

    if ((path = build_path(mrb, search_path[i], srcname)) == NULL) {
      continue;
    }

    if ((fp = fopen(path, "rb")) == NULL) {
      mrb_free(mrb, path);
      path = NULL;
      continue;
    }
    fclose(fp);
    break;
  }

  mrb_free(mrb, (void *)search_path[1]);

  return path;
}

int32_t
mrb_debug_list(mrb_state *mrb, mrb_debug_context *dbg, char *filename, uint16_t line_min, uint16_t line_max)
{
  char *ext;
  source_file *file;

  if (mrb == NULL || dbg == NULL || filename == NULL) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  ext = strrchr(filename, '.');

  if (ext == NULL || strcmp(ext, ".rb")) {
    printf("List command only supports .rb file.\n");
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  if (line_min > line_max) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  if ((file = source_file_new(mrb, dbg, filename)) != NULL) {
    show_lines(file, line_min, line_max);
    source_file_free(mrb, file);
    return MRB_DEBUG_OK;
  }
  else {
    printf("Invalid source file named %s.\n", filename);
    return MRB_DEBUG_INVALID_ARGUMENT;
  }
}
