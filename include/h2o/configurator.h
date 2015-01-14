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
 */
#ifndef h2o__configurator_h
#define h2o__configurator_h

#include "yoml.h"

enum {
    H2O_CONFIGURATOR_FLAG_GLOBAL = 0x1,
    H2O_CONFIGURATOR_FLAG_HOST = 0x2,
    H2O_CONFIGURATOR_FLAG_PATH = 0x4,
    H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR = 0x100,
    H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE = 0x200,
    H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING = 0x400,
    H2O_CONFIGURATOR_FLAG_DEFERRED = 0x1000
};

#define H2O_CONFIGURATOR_NUM_LEVELS 3

typedef struct h2o_configurator_context_t {
    h2o_globalconf_t *globalconf;
    h2o_hostconf_t *hostconf;
    h2o_pathconf_t *pathconf;
} h2o_configurator_context_t;

typedef int (*h2o_configurator_dispose_cb)(h2o_configurator_t *configurator);
typedef int (*h2o_configurator_enter_cb)(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node);
typedef int (*h2o_configurator_exit_cb)(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node);
typedef int (*h2o_configurator_command_cb)(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node);

struct st_h2o_configurator_command_t {
    /**
     * configurator to which the command belongs
     */
    h2o_configurator_t *configurator;
    /**
     * name of the command handled by the configurator
     */
    const char *name;
    /**
     * flags
     */
    int flags;
    /**
     * mandatory callback called to handle the command
     */
    h2o_configurator_command_cb cb;
    /**
     * multi-line string describing of the command (printed by h2o --help)
     */
    const char *description;
};

/**
 * basic structure of a configurator (handles a configuration command)
 */
struct st_h2o_configurator_t {
    h2o_linklist_t _link;
    /**
     * optional callback called when the global config is being disposed
     */
    h2o_configurator_dispose_cb dispose;
    /**
     * optional callback called before the configuration commands are handled
     */
    h2o_configurator_enter_cb enter;
    /**
     * optional callback called after all the configuration commands are handled
     */
    h2o_configurator_exit_cb exit;
    /**
     * list of commands
     */
    H2O_VECTOR(h2o_configurator_command_t) commands;
};

/**
 * registers a configurator
 */
h2o_configurator_t *h2o_configurator_create(h2o_globalconf_t *conf, size_t sz);
/**
 *
 */
void h2o_configurator_define_command(h2o_configurator_t *configurator, const char *name, int flags, h2o_configurator_command_cb cb, const char *desc);
/**
 * returns a configurator of given command name
 * @return configurator for given name or NULL if not found
 */
h2o_configurator_command_t *h2o_configurator_get_command(h2o_globalconf_t *conf, const char *name);
/**
 * applies the configuration to the context
 * @return 0 if successful, -1 if not
 */
int h2o_configurator_apply(h2o_globalconf_t *config, yoml_t *node);
/**
 * emits configuration error
 */
void h2o_configurator_errprintf(h2o_configurator_command_t *cmd, yoml_t *node, const char *reason, ...) __attribute__((format (printf, 3, 4)));
/**
 * interprets the configuration value using sscanf, or prints an error upon failure
 * @param configurator configurator
 * @param node configuration value
 * @param fmt scanf-style format string
 * @return 0 if successful, -1 if not
 */
int h2o_configurator_scanf(h2o_configurator_command_t *cmd, yoml_t *node, const char *fmt, ...) __attribute__((format (scanf, 3, 4)));
/**
 * interprets the configuration value and returns the index of the matched string within the candidate strings, or prints an error upon failure
 * @param configurator configurator
 * @param node configuration value
 * @param candidates a comma-separated list of strings (should not contain whitespaces)
 * @return index of the matched string within the given list, or -1 if none of them matched
 */
ssize_t h2o_configurator_get_one_of(h2o_configurator_command_t *cmd, yoml_t *node, const char *candidates);

void h2o_configurator__init_core(h2o_globalconf_t *conf);
void h2o_configurator__dispose_configurators(h2o_globalconf_t *conf);

#endif
