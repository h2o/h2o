# Minimal CMake project for building a static library under Windows.

cmake_minimum_required (VERSION 2.8)
project (yaml C)

set (YAML_VERSION_MAJOR 0)
set (YAML_VERSION_MINOR 1)
set (YAML_VERSION_PATCH 6)
set (YAML_VERSION_STRING "${YAML_VERSION_MAJOR}.${YAML_VERSION_MINOR}.${YAML_VERSION_PATCH}")

file (GLOB SRC src/*.c)

include_directories (include win32)
add_definitions (-DHAVE_CONFIG_H -DYAML_DECLARE_STATIC)
add_library (yaml STATIC ${SRC})

