#!/usr/bin/env ruby

Dir.chdir(File.dirname($0))

e = File.open("known_errors_e2c.cstub", "w")
d = File.open("known_errors_def.cstub", "w")

IO.readlines("known_errors.def").each { |name|
  next if name =~ /^#/
  name.strip!

  e.write <<CODE
#ifdef #{name}
  { #{name}, NULL, },
#endif
CODE

  d.write <<CODE
#ifdef #{name}
  itsdefined(#{name});
#else
  itsnotdefined(#{name});
#endif
CODE
}
