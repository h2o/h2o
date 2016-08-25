# Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
class TrieAddr
  def self.generate_leaf(default=nil)
    leaf = Hash.new
    leaf.default = default || leaf
    (0..255).each {|i| leaf[i.to_s] = leaf }
    return leaf
  end
  REJECT  = self.generate_leaf
  FULFILL = self.generate_leaf(REJECT)

  def initialize
    @root = Hash.new(REJECT)
  end

  def add(cidr)
    if cidr.kind_of?(Array)
      cidr.each {|c| add(c) }
      return self
    end

    ip, length = cidr.split('/', 2)
    s = ip.split(".", 4).map {|o| o.to_i}
    if s.length != 4
      raise ArgumentError, "invalid IPv4 address: #{ip}"
    end
    length = (length || 32).to_i

    netmask = ~((1 << (32 - length)) - 1) & 0xffffffff
    nip = (s[0] << 24) + (s[1] << 16) + (s[2] << 8) + s[3]
    nip &= netmask

    cur = @root
    while length > 8 do
      octet = ((nip >> 24) & 0xff).to_s
      return self if cur[octet].equal?(FULFILL)
      if !cur[octet] || cur[octet].equal?(REJECT)
        cur[octet] = Hash.new(REJECT)
      end
      cur = cur[octet]
      nip <<= 8
      length -= 8
    end
    lower = (nip >> 24) & 0xff
    upper = lower + (1 << (8 - length)) - 1;
    (lower..upper).each {|t| cur[t.to_s] = FULFILL }
    return self
  end

  def match?(ip)
    s = ip.split(".", 4)
    @root[s[0]][s[1]][s[2]][s[3]].equal?(FULFILL)
  end
end
