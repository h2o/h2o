#!/usr/bin/env ruby

Dir.chdir(File.dirname($0))

f = File.open("const.cstub", "w")

IO.readlines("const.def").each { |name|
  name.sub(/^#.*/, "")
  name.strip!
  next if name.empty?

  f.write <<CODE
#if defined(#{name})#{name.start_with?('IPPROTO_') ? ' || defined(_WINSOCKAPI_)' : ''}
  define_const(#{name});
#endif
CODE
}
