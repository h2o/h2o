##
# Kernel
#
# ISO 15.3.1
module Kernel
  ##
  # Print human readable object description
  #
  # ISO 15.3.1.2.9
  # ISO 15.3.1.3.34
  def p(*args)
    i = 0
    len = args.size
    while i < len
      __printstr__ args[i].inspect
      __printstr__ "\n"
      i += 1
    end
    args.__svalue
  end

  def printf(*args)
    __printstr__(sprintf(*args))
    nil
  end
end
