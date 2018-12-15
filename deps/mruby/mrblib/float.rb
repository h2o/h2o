##
# Float
#
# ISO 15.2.9
class Float
  # mruby special - since mruby integers may be upgraded to floats,
  # floats should be compatible to integers.
  include Integral
end if class_defined?("Float")
