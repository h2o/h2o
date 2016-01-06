# based on public-domain code by cho45
#
# Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
class Htpasswd

  attr_accessor :path
  attr_accessor :realm

  def initialize(path, realm)
    @path = path
    @realm = realm
  end

  def call(env)
    if /\/\.ht/.match(env['PATH_INFO'])
      return [ 404, { "Content-Type" => "text/plain" }, [ "not found" ] ]
    end
    auth = env['HTTP_AUTHORIZATION']
    if auth
      method, cred = *auth.split(' ')
      if method.casecmp("basic") == 0
        user, pass = cred.unpack("m")[0].split(':', 2)
        begin
          if lookup(user, pass)
            return [ 399, { "x-fallthru-set-remote-user" => user }, [] ]
          end
        rescue => e
          $stderr.puts "failed to validate password using file:#{@path}:#{e.message}"
          return [ 500, { "Content-Type" => "text/plain" }, [ "Internal Server Error" ] ]
        end
      end
    end
    return [ 401, { "Content-Type" => "text/plain", "WWW-Authenticate" => "Basic realm=\"#{@realm}\"" }, [ "Authorization Required" ] ]
  end

  def lookup(user, pass)
    File.open(@path) do |file|
      file.each_line do |line|
        line_user, hash = line.chomp.split(':', 2)
        if user == line_user && self.class.validate(pass, hash)
          return true
        end
      end
    end
    return false
  end

  def Htpasswd.crypt_md5(pass, salt)
    ctx = Digest::MD5.new.update("#{pass}$apr1$#{salt}")
    final = Digest::MD5.new.update("#{pass}#{salt}#{pass}").digest!.bytes

    l = pass.length
    while l > 0
      ctx.update(final[0 .. (l > 16 ? 16 : l) - 1].pack("C*"))
      l -= 16
    end

    l = pass.length
    while l > 0
      ctx.update(l % 2 != 0 ? "\0" : pass[0])
      l >>= 1
    end

    final = ctx.digest!

    1000.times do |i|
      ctx = Digest::MD5.new
      ctx.update(i % 2 != 0 ? pass : final)
      ctx.update(salt) if i % 3 != 0
      ctx.update(pass) if i % 7 != 0
      ctx.update(i % 2 != 0 ? final : pass)
      final = ctx.digest!
    end

    final = final.bytes
    hash = ""
    for a, b, c in [[0, 6, 12], [1, 7, 13], [2, 8, 14], [3, 9, 15], [4, 10, 5]]
      hash << _to64(final[a] << 16 | final[b] << 8 | final[c], 4)
    end
    hash << _to64(final[11], 2)

    "$apr1$#{salt}$#{hash}"
  end

  def Htpasswd._to64(v, n)
    chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    output = ""
    n.times do
      output << chars[v & 0x3f]
      v >>= 6
    end
    output
  end

  def Htpasswd.crypt_sha1(pass)
    "{SHA}" + [Digest::SHA1.new.update(pass).digest!].pack("m").chomp
  end

  def Htpasswd.validate(pass, hash)
    if /^\$apr1\$(.*)\$/.match(hash)
      encoded = crypt_md5(pass, $1)
    elsif /^{SHA}/.match(hash)
      encoded = crypt_sha1(pass)
    else
      raise "crypt-style password hash is not supported"
    end
    return encoded == hash
  end

end
