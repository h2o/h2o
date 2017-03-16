import os

c, link, asm, utils = emk.module("c", "link", "asm", "utils")

default_compile_flags = ["-fvisibility=hidden", "-Wall", "-Wextra", "-Wshadow", "-Werror", "-Wno-missing-field-initializers", "-Wno-unused-parameter", \
    "-Wno-comment", "-Wno-unused", "-Wno-unknown-pragmas"]
default_link_flags = []
opt_flags = {"dbg":["-g"], "std":["-O2"], "max":["-O3"], "small":["-Os"]}
opt_link_flags = {"dbg":[], "std":[], "max":[], "small":[]}
c_flags = ["-std=c99"]
cxx_flags = ["-std=c++11", "-Wno-reorder", "-fno-rtti", "-fno-exceptions"]
c_link_flags = []
cxx_link_flags = ["-fno-rtti", "-fno-exceptions"]

def setup_build_dir():
    build_arch = None
    if "arch" in emk.options:
        build_arch = emk.options["arch"]
    elif not emk.cleaning:
        build_arch = "osx"
    emk.options["arch"] = build_arch

    opt_level = None
    if "opt" in emk.options:
        level = emk.options["opt"]
        if level in opt_flags:
            opt_level = level
        else:
            emk.log.warning("Unknown optimization level '%s'" % (level))
    elif not emk.cleaning:
        opt_level = "dbg"
    emk.options["opt"] = opt_level

    dirs = ["__build__"]
    if build_arch:
        dirs.append(build_arch)
    if opt_level:
        dirs.append(opt_level)
    emk.build_dir = os.path.join(*dirs)

def setup_osx():
    global c
    global link

    flags = [("-arch", "x86_64"), "-fno-common", "-Wnewline-eof"]
    c.flags.extend(flags)
    c.cxx.flags += ["-stdlib=libc++"]
    link.cxx.flags += ["-stdlib=libc++"]

    link_flags = [("-arch", "x86_64")]
    link.local_flags.extend(link_flags)

def setup_avr():
    global c
    global link

    c.compiler = c.GccCompiler("/Projects/avr-tools/bin/avr-")
    c.flags += ["-mmcu=atmega256rfr2", "-ffunction-sections", "-fdata-sections"]
    link.linker = link.GccLinker("/Projects/avr-tools/bin/avr-")
    link.flags += ["-mmcu=atmega256rfr2", "-mrelax", "-Wl,--gc-sections"]
    link.strip = True

def setup_arm_thumb():
    global c
    global link
    global asm
    global utils

    asm.assembler = asm.GccAssembler("/cross/arm_cortex/bin/arm-none-eabi-")
    c.compiler = c.GccCompiler("/cross/arm_cortex/bin/arm-none-eabi-")
    link.linker = link.GccLinker("/cross/arm_cortex/bin/arm-none-eabi-")

    c.flags.extend(["-mcpu=cortex-m0", "-mthumb", "-ffunction-sections", "-fdata-sections", "-fno-builtin-fprintf", "-fno-builtin-printf"])
    c.defines["LPC11XX"] = 1
    
    link.local_flags.extend(["-mcpu=cortex-m0", "-mthumb", "-nostartfiles", "-nostdlib", "-Wl,--gc-sections"])
    link.local_flags.extend(["-Tflash.lds", "-L/Projects/lpc11xx/core", "/Projects/lpc11xx/core/" + emk.build_dir + "/board_cstartup.o"])
    link.local_syslibs += ["gcc"]
    link.depdirs += ["/Projects/lpc11xx/stdlib"]

    def do_objcopy(produces, requires):
        utils.call("/cross/arm_cortex/bin/arm-none-eabi-objcopy", "-O", "binary", requires[0], produces[0])

    def handle_exe(path):
        emk.depend(path, "/Projects/lpc11xx/core/" + emk.build_dir + "/board_cstartup.o")
        emk.rule(do_objcopy, path + ".bin", path, cwd_safe=True, ex_safe=True)
        emk.autobuild(path + ".bin")

    link.exe_funcs.append(handle_exe)
    link.strip = True
    
    emk.recurse("/Projects/lpc11xx/core")

def setup_linux_rpi():
    global c
    global link

    c.compiler = c.GccCompiler("/Volumes/xtools/arm-none-linux-gnueabi/bin/arm-none-linux-gnueabi-")
    link.linker = link.GccLinker("/Volumes/xtools/arm-none-linux-gnueabi/bin/arm-none-linux-gnueabi-")
    
    c.flags.extend(["-fomit-frame-pointer"])

setup_build_dir()

setup_funcs = {"osx":setup_osx, "avr":setup_avr, "arm_thumb":setup_arm_thumb, "rpi": setup_linux_rpi}

if not emk.cleaning:
    build_arch = emk.options["arch"]
    opt_level = emk.options["opt"]

    c.flags.extend(default_compile_flags)
    c.flags.extend(opt_flags[opt_level])
    c.c.flags.extend(c_flags)
    c.cxx.flags.extend(cxx_flags)
    link.local_flags.extend(default_link_flags)
    link.local_flags.extend(opt_link_flags[opt_level])
    link.c.local_flags.extend(c_link_flags)
    link.cxx.local_flags.extend(cxx_link_flags)

    c.include_dirs.append("$:proj:$")

    if build_arch in setup_funcs:
        setup_funcs[build_arch]()
    else:
        raise emk.BuildError("Unknown target arch '%s'" % (build_arch))

    c.defines["TARGET_ARCH_" + build_arch.upper()] = 1
