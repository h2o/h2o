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

  # 15.3.1.2.10
  # 15.3.1.3.35
  def print(*args)
    i = 0
    len = args.size
    while i < len
      __printstr__ args[i].to_s
      i += 1
    end
  end

  # 15.3.1.2.11
  # 15.3.1.3.39
  def puts(*args)
    i = 0
    len = args.size
    while i < len
      s = args[i]
      if s.kind_of?(Array)
        puts(*s)
      else
        s = s.to_s
        __printstr__ s
        __printstr__ "\n" if (s[-1] != "\n")
      end
      i += 1
    end
    __printstr__ "\n" if len == 0
    nil
  end

  def printf(*args)
    __printstr__(sprintf(*args))
    nil
  end
end
