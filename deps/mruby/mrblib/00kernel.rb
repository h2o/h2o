module Kernel
  ##
  # call-seq:
  #    obj.extend(module, ...)    -> obj
  #
  # Adds to _obj_ the instance methods from each module given as a
  # parameter.
  #
  #    module Mod
  #      def hello
  #        "Hello from Mod.\n"
  #      end
  #    end
  #
  #    class Klass
  #      def hello
  #        "Hello from Klass.\n"
  #      end
  #    end
  #
  #    k = Klass.new
  #    k.hello         #=> "Hello from Klass.\n"
  #    k.extend(Mod)   #=> #<Klass:0x401b3bc8>
  #    k.hello         #=> "Hello from Mod.\n"
  #
  # ISO 15.3.1.3.13
  def extend(*args)
    args.reverse!
    args.each do |m|
      m.extend_object(self)
      m.extended(self)
    end
    self
  end
end
