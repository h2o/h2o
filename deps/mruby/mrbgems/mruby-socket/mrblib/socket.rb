class Addrinfo
  def initialize(sockaddr, family=Socket::PF_UNSPEC, socktype=0, protocol=0)
    @hostname = nil
    if sockaddr.is_a? Array
      sary = sockaddr
      if sary[0] == 'AF_INET' || sary[0] == 'AF_INET6'
        @sockaddr = Socket.sockaddr_in(sary[1], sary[3])
        @hostname = sary[2]
      elsif sary[0] == 'AF_UNIX'
        @sockaddr = Socket.sockaddr_un(sary[1])
      end
    else
      @sockaddr = sockaddr.dup
    end
    if family == Socket::PF_UNSPEC or family == nil
      @family = Socket._sockaddr_family(@sockaddr)
    else
      @family = family
    end
    @socktype = socktype
    @protocol = protocol
    @canonname = nil
  end

  def self.foreach(nodename, service, family=nil, socktype=nil, protocol=nil, flags=0, &block)
    a = self.getaddrinfo(nodename, service, family, socktype, protocol, flags)
    a.each { |ai| block.call(ai) }
    a
  end

  def self.ip(host)
    Addrinfo.new(Socket.sockaddr_in(0, host))
  end

  def self.tcp(host, port)
    Addrinfo.getaddrinfo(host, port, nil, Socket::SOCK_STREAM, Socket::IPPROTO_TCP)[0]
  end

  def self.udp(host, port)
    Addrinfo.getaddrinfo(host, port, nil, Socket::SOCK_DGRAM, Socket::IPPROTO_UDP)[0]
  end

  def self.unix(path, socktype=Socket::SOCK_STREAM)
    Addrinfo.new(Socket.sockaddr_un(path), Socket::AF_UNIX, socktype)
  end

  def afamily
    @family
  end

  #def bind

  attr_reader :canonname

  #def connect
  #def connect_from
  #def connect_to

  #def family_addrinfo(host, port=nil)
  #def getnameinfo(flags=0)
  #  Socket.getnameinfo
  #end

  def inspect
    if ipv4? or ipv6?
      if @protocol == Socket::IPPROTO_TCP or (@socktype == Socket::SOCK_STREAM and @protocol == 0)
        proto = 'TCP'
      elsif @protocol == Socket::IPPROTO_UDP or (@socktype == Socket::SOCK_DGRAM and @protocol == 0)
        proto = 'UDP'
      else
        proto = '???'
      end
      "#<Addrinfo: #{inspect_sockaddr} #{proto}>"
    else
      "#<Addrinfo: #{self.unix_path} SOCK_STREAM>"
    end
  end

  def inspect_sockaddr
    if ipv4?
      a, p = ip_unpack
      "#{a}:#{p}"
    elsif ipv6?
      a, p = ip_unpack
      "[#{a}]:#{p}"
    elsif unix?
      unix_path
    else
      '???'
    end
  end

  def ip?
    ipv4? or ipv6?
  end

  def ip_address
    ip_unpack[0]
  end

  def ip_port
    ip_unpack[1]
  end

  def ip_unpack
    h, p = getnameinfo(Socket::NI_NUMERICHOST|Socket::NI_NUMERICSERV)
    [ h, p.to_i ]
  end

  def ipv4?
    @family == Socket::AF_INET
  end

  #def ipv4_loopback?
  #def ipv4_multicast?
  #def ipv4_private?

  def ipv6?
    @family == Socket::AF_INET6
  end

  #def ipv6_loopback?
  #def ipv6_mc_global?
  #def ipv6_mc_linklocal?
  #def ipv6_mc_nodelocal?
  #def ipv6_mc_orilocal?
  #def ipv6_mc_sitelocal?
  #def ipv6_multicast?
  #def ipv6_to_ipv4
  #def ipv6_unspecified
  #def ipv6_v4compat?
  #def ipv6_v4mapped?
  #def listen(backlog=5)

  def pfamily
    @family
  end

  attr_reader :protocol
  attr_reader :socktype

  def _to_array
    case @family
    when Socket::AF_INET
      s = "AF_INET"
    when Socket::AF_INET6
      s = "AF_INET6"
    when Socket::AF_UNIX
      s = "AF_UNIX"
    else
      s = "(unknown AF)"
    end
    addr, port = self.getnameinfo(Socket::NI_NUMERICHOST|Socket::NI_NUMERICSERV)
    [ s, port.to_i, addr, addr ]
  end

  def to_sockaddr
    @sockaddr
  end

  alias to_s to_sockaddr

  def unix?
    @family == Socket::AF_UNIX
  end
end

class BasicSocket < IO
  @@do_not_reverse_lookup = true

  def self.do_not_reverse_lookup
    @@do_not_reverse_lookup
  end

  def self.do_not_reverse_lookup=(val)
    @@do_not_reverse_lookup = val ? true : false
  end

  def initialize(*args)
    super(*args)
    self._is_socket = true
    @do_not_reverse_lookup = @@do_not_reverse_lookup
  end

  def self.for_fd(fd)
    super(fd, "r+")
  end

  #def connect_address

  def local_address
    Addrinfo.new self.getsockname
  end

  def recv_nonblock(maxlen, flags=0)
    begin
      _setnonblock(true)
      recv(maxlen, flags)
    ensure
      _setnonblock(false)
    end
  end

  def remote_address
    Addrinfo.new self.getpeername
  end

  attr_accessor :do_not_reverse_lookup
end

class IPSocket < BasicSocket
  def self.getaddress(host)
    Addrinfo.ip(host).ip_address
  end

  def addr
    Addrinfo.new(self.getsockname)._to_array
  end

  def peeraddr
    Addrinfo.new(self.getpeername)._to_array
  end

  def recvfrom(maxlen, flags=0)
    msg, sa = _recvfrom(maxlen, flags)
    [ msg, Addrinfo.new(sa)._to_array ]
  end
end

class TCPSocket < IPSocket
  def initialize(host, service, local_host=nil, local_service=nil)
    if @init_with_fd
      super(host, service)
    else
      s = nil
      e = SocketError
      Addrinfo.foreach(host, service) { |ai|
        begin
          s = Socket._socket(ai.afamily, Socket::SOCK_STREAM, 0)
          if local_host or local_service
            local_host ||= (ai.afamily == Socket::AF_INET) ? "0.0.0.0" : "::"
            local_service ||= "0"
            bi = Addrinfo.getaddrinfo(local_host, local_service, ai.afamily, ai.socktype)[0]
            Socket._bind(s, bi.to_sockaddr)
          end
          Socket._connect(s, ai.to_sockaddr)
          super(s, "r+")
          return
        rescue => e0
          e = e0
        end
      }
      raise e
    end
  end

  def self.new_with_prelude pre, *args
    o = self._allocate
    o.instance_eval(&pre)
    o.initialize(*args)
    o
  end

  #def self.gethostbyname(host)
end

class TCPServer < TCPSocket
  def initialize(host=nil, service)
    ai = Addrinfo.getaddrinfo(host, service, nil, nil, nil, Socket::AI_PASSIVE)[0]
    @init_with_fd = true
    super(Socket._socket(ai.afamily, Socket::SOCK_STREAM, 0), "r+")
    if Socket.const_defined?(:SO_REUSEADDR)
      self.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
    end
    Socket._bind(self.fileno, ai.to_sockaddr)
    listen(5)
    self
  end

  def accept
    fd = self.sysaccept
    begin
      TCPSocket.new_with_prelude(proc { @init_with_fd = true }, fd, "r+")
    rescue
      IO._sysclose(fd) rescue nil
      raise
    end
  end

  def accept_nonblock
    begin
      self._setnonblock(true)
      self.accept
    ensure
      self._setnonblock(false)
    end
  end

  def listen(backlog)
    Socket._listen(self.fileno, backlog)
    0
  end

  def sysaccept
    Socket._accept(self.fileno)
  end
end

class UDPSocket < IPSocket
  def initialize(af=Socket::AF_INET)
    super(Socket._socket(af, Socket::SOCK_DGRAM, 0), "r+")
    @af = af
    self
  end

  def bind(host, port)
    Socket._bind(self.fileno, _sockaddr_in(port, host))
    0
  end

  def connect(host, port)
    Socket._connect(self.fileno, _sockaddr_in(port, host))
    0
  end

  def recvfrom_nonblock(*args)
    s = self
    begin
      self._setnonblock(true)
      self.recvfrom(*args)
    ensure
      # XXX: self is a SystemcallException here! (should be bug)
      s._setnonblock(false)
    end
  end

  def send(mesg, flags, host=nil, port=nil)
    if port
      super(mesg, flags, _sockaddr_in(port, host))
    elsif host
      super(mesg, flags, host)
    else
      super(mesg, flags)
    end
  end

  def _sockaddr_in(port, host)
    ai = Addrinfo.getaddrinfo(host, port, @af, Socket::SOCK_DGRAM)[0]
    ai.to_sockaddr
  end
end

class Socket < BasicSocket
  def initialize(domain, type, protocol=0)
    super(Socket._socket(domain, type, protocol), "r+")
  end

  #def self.accept_loop

  def self.getaddrinfo(nodename, servname, family=nil, socktype=nil, protocol=nil, flags=0)
    Addrinfo.getaddrinfo(nodename, servname, family, socktype, protocol, flags).map { |ai|
      ary = ai._to_array
      ary[2] = nodename
      ary[4] = ai.afamily
      ary[5] = ai.socktype
      ary[6] = ai.protocol
      ary
    }
  end

  #def self.getnameinfo
  #def self.ip_address_list

  def self.open(*args)
    new(args)
  end

  def self.sockaddr_in(port, host)
    ai = Addrinfo.getaddrinfo(host, port, nil, Socket::SOCK_DGRAM)[0]
    ai.to_sockaddr
  end

  #def self.tcp
  #def self.tcp_server_loop
  #def self.tcp_server_sockets
  #def self.udp_server_loop
  #def self.udp_server_loop_on
  #def self.udp_server_recv
  #def self.udp_server_sockets
  #def self.unix(path)
  #def self.unix_server_loop
  #def self.unix_server_socket

  def self.unpack_sockaddr_in(sa)
    Addrinfo.new(sa).ip_unpack.reverse
  end

  def self.unpack_sockaddr_un(sa)
    Addrinfo.new(sa).unix_path
  end

  class << self
    alias pack_sockaddr_in sockaddr_in
    alias pack_sockaddr_un sockaddr_un
    alias pair socketpair
  end

  def accept
    fd, addr = self.sysaccept
    [ Socket.for_fd(fd), addr ]
  end

  def accept_nonblock
    begin
      self._setnonblock(true)
      self.accept
    ensure
      self._setnonblock(false)
    end
  end

  def bind(sockaddr)
    sockaddr = sockaddr.to_sockaddr if sockaddr.is_a? Addrinfo
    Socket._bind(self.fileno, sockaddr)
    0
  end

  def connect(sockaddr)
    sockaddr = sockaddr.to_sockaddr if sockaddr.is_a? Addrinfo
    Socket._connect(self.fileno, sockaddr)
    0
  end

  def connect_nonblock(sockaddr)
    begin
      self._setnonblock(true)
      self.connect(sockaddr)
    ensure
      self._setnonblock(false)
    end
  end

  #def ipv6only!

  def listen(backlog)
    Socket._listen(self.fileno, backlog)
    0
  end

  def recvfrom(maxlen, flags=0)
    msg, sa = _recvfrom(maxlen, flags)
    socktype = self.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE).int
    [ msg, Addrinfo.new(sa, Socket::PF_UNSPEC, socktype) ]
  end

  def recvfrom_nonblock(*args)
    begin
      self._setnonblock(true)
      self._recvfrom(*args)
    ensure
      self._setnonblock(false)
    end
  end

  def sysaccept
    Socket._accept2(self.fileno)
  end
end

class UNIXSocket < BasicSocket
  def initialize(path, &block)
    if self.is_a? UNIXServer
      super(path, "r")
    else
      super(Socket._socket(Socket::AF_UNIX, Socket::SOCK_STREAM, 0), "r+")
      Socket._connect(self.fileno, Socket.sockaddr_un(path))

      if block_given?
        begin
          yield self
        ensure
          begin
            self.close unless self.closed?
          rescue StandardError
          end
        end
      end
    end
  end

  def self.socketpair(type=Socket::SOCK_STREAM, protocol=0)
    a = Socket.socketpair(Socket::AF_UNIX, type, protocol)
    [ UNIXSocket.for_fd(a[0]), UNIXSocket.for_fd(a[1]) ]
  end

  class << self
    alias pair socketpair
  end

  def addr
    [ "AF_UNIX", path ]
  end

  def path
    Addrinfo.new(self.getsockname).unix_path
  end

  def peeraddr
    [ "AF_UNIX", Addrinfo.new(self.getpeername).unix_path ]
  end

  #def recv_io

  def recvfrom(maxlen, flags=0)
    msg, sa = _recvfrom(maxlen, flags)
    path = (sa.size > 0) ? Addrinfo.new(sa).unix_path : ""
    [ msg, [ "AF_UNIX", path ] ]
  end

  #def send_io
end

class UNIXServer < UNIXSocket
  def initialize(path)
    fd = Socket._socket(Socket::AF_UNIX, Socket::SOCK_STREAM, 0)
    begin
      super(fd)
      Socket._bind(fd, Socket.pack_sockaddr_un(path))
      self.listen(5)
    rescue => e
      IO._sysclose(fd) rescue nil
      raise e
    end

    if block_given?
      begin
        yield self
      ensure
        self.close rescue nil unless self.closed?
      end
    end
  end

  def accept
    fd = self.sysaccept
    begin
      sock = UNIXSocket.for_fd(fd)
    rescue
      IO._sysclose(fd) rescue nil
    end
    sock
  end

  def accept_nonblock
    begin
      self._setnonblock(true)
      self.accept
    ensure
      self._setnonblock(false)
    end
  end

  def listen(backlog)
    Socket._listen(self.fileno, backlog)
    0
  end

  def sysaccept
    Socket._accept(self.fileno)
  end
end

class Socket
  include Constants
end

class Socket
  class Option
    def initialize(family, level, optname, data)
      @family  = family
      @level   = level
      @optname = optname
      @data    = data
    end

    def self.bool(family, level, optname, bool)
      self.new(family, level, optname, [(bool ? 1 : 0)].pack('i'))
    end

    def self.int(family, level, optname, integer)
      self.new(family, level, optname, [integer].pack('i'))
    end

    #def self.linger(family, level, optname, integer)
    #end

    attr_reader :data, :family, :level, :optname

    def bool
      @data.unpack('i')[0] != 0
    end

    def inspect
      "#<Socket::Option: family:#{@family} level:#{@level} optname:#{@optname} #{@data.inspect}>"
    end

    def int
      @data.unpack('i')[0]
    end

    def linger
      raise NotImplementedError.new
    end

    def unpack(template)
      raise NotImplementedError.new
    end
  end
end

class SocketError < StandardError; end
