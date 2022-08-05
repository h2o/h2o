#!/usr/bin/env ruby

Dir.chdir(File.dirname($0))

d = File.open("known_errors_def.cstub", "w")

IO.readlines("known_errors.def").each { |name|
  next if name =~ /^#/
  name.strip!

  d.write <<CODE
#ifdef #{name}
  itsdefined(#{name}, MRB_SYM(#{name}))
#else
  itsnotdefined(#{name}, MRB_SYM(#{name}))
#endif
CODE
}
