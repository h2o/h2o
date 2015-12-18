##
# Digest Test

if Object.const_defined?(:Digest)
  assert('Digest') do
    Digest.class == Module
  end

  assert('Digest::Base') do
    Digest::Base.class == Class
  end

  assert('Digest::Base#new') do
    e1 = nil
    begin
      Digest::Base.new
    rescue NotImplementedError => e
      e1 = e
    end
    e1.class == NotImplementedError
  end

  assert('Digest::MD5') do
    Digest::MD5.class == Class
  end

  assert('Digest::MD5 superclass') do
    Digest::MD5.superclass == Digest::Base
  end

  assert('Digest::MD5.digest') do
    Digest::MD5.digest('ruby') == "X\xE5=\x13$\xEE\xF6&_\xDB\x97\xB0\x8E\xD9\xAA\xDF"
  end

  #assert('Digest::MD5.file')

  assert('Digest::MD5.hexdigest') do
    Digest::MD5.hexdigest('ruby') == "58e53d1324eef6265fdb97b08ed9aadf"
  end

  assert('Digest::MD5#update') do
    d = Digest::MD5.new
    d.update('ruby')
    d.hexdigest == "58e53d1324eef6265fdb97b08ed9aadf"
  end

  assert('Digest::MD5#update 2') do
    d = Digest::MD5.new
    d.update('ruby')
    d.update('digest')
    d.hexdigest == "2ac1b3e3db06239e3244817f281450f1"
  end

  assert('Digest::MD5#<<') do
    a = Digest::MD5.new
    b = Digest::MD5.new
    a.update('ruby')
    b << "r" << "u" << "b" << "y"
    a.hexdigest == b.hexdigest
  end

  assert('Digest::MD5#== with Digest::XXX') do
    x1 = Digest::MD5.new.update("ruby")
    x2 = Digest::MD5.new.update("ruby")
    x3 = Digest::MD5.new.update("RUBY")
    (x1 == x2) == true and
    (x1 == x3) == false
  end

  assert('Digest::MD5#== with String') do
    Digest::MD5.new.update("ruby") == "58e53d1324eef6265fdb97b08ed9aadf"
  end

  assert('Digest::MD5#block_length') do
    Digest::MD5.new.block_length == 64
  end

  assert('Digest::MD5#digest') do
    Digest::MD5.new.update("ruby").digest == "X\xE5=\x13$\xEE\xF6&_\xDB\x97\xB0\x8E\xD9\xAA\xDF"
  end

  assert('Digest::MD5#digest!') do
    d = Digest::MD5.new.update("ruby")
    d.digest!
    #d.digest! == "\xD4\x1D\x8C\xD9\x8F\x00\xB2\x04\xE9\x80\t\x98\xEC\xF8B~"
    # XXX: mrbtest dumps core!
    d.digest! == Digest::MD5.new.digest
  end

  assert('Digest::MD5#digest_length') do
    d = Digest::MD5.new
    n = 16
    d.digest_length == n and
    d.length == n and
    d.size == n
  end

  #assert('Digest::MD5#file')

  assert('Digest::MD5#hexdigest') do
    d = Digest::MD5.new.update("ruby")
    s = "58e53d1324eef6265fdb97b08ed9aadf"
    d.hexdigest == s and
    d.to_s == s
  end

  assert('Digest::MD5#hexdigest!') do
    d = Digest::MD5.new.update("ruby")
    d.hexdigest!
    d.hexdigest! == "d41d8cd98f00b204e9800998ecf8427e"
  end

  assert('Digest::MD5#reset') do
    d = Digest::MD5.new.update("ruby")
    d.reset
    d.hexdigest! == "d41d8cd98f00b204e9800998ecf8427e"
  end

  if Digest.const_defined? :RMD160
    assert('Digest::RMD160#hexdigest') do
      d = Digest::RMD160.new.update("ruby")
      s = "29d9b710bc50866fa2399c3061cd02c0c8ffa197"
      d.hexdigest == s
    end
  end

  if Digest.const_defined? :SHA1
    assert('Digest::SHA1#hexdigest') do
      d = Digest::SHA1.new.update("ruby")
      s = "18e40e1401eef67e1ae69efab09afb71f87ffb81"
      d.hexdigest == s
    end
  end

  if Digest.const_defined? :SHA256
    assert('Digest::SHA256#hexdigest') do
      d = Digest::SHA256.new.update("ruby")
      s = "b9138194ffe9e7c8bb6d79d1ed56259553d18d9cb60b66e3ba5aa2e5b078055a"
      d.hexdigest == s
    end
  end

  if Digest.const_defined? :SHA384
    assert('Digest::SHA384#hexdigest') do
      d = Digest::SHA384.new.update("ruby")
      s = "635365ef93ebf2c7a4e40b0b497da727ab8c2914eb9f052e6be40476f95d3daf44786790f5f0e843fab419b43022e069"
      d.hexdigest == s
    end
  end

  if Digest.const_defined? :SHA512
    assert('Digest::SHA512#hexdigest') do
      d = Digest::SHA512.new.update("ruby")
      s = "423408d7723a3d80baefa804bd50b61a89667efec1713386a7b8efe28e5d13968307a908778cad210d7aa2dfe7db9a2aa86895f9fc1eeefcc99814310b207a6b"
      d.hexdigest == s
    end
  end

  assert('Digest::HMAC') do
    Digest::HMAC.class == Class
  end

  assert('Digest::HMAC.digest') do
    Digest::HMAC.digest("data", "hash key", Digest::SHA1) == "\xFD \xECC=\xFD\x97\x0E\xEC!FW\xCF\xB5Gl]\x913f"
  end

  assert('Digest::HMAC.hexdigest') do
    Digest::HMAC.hexdigest("data", "hash key", Digest::SHA1) == "fd20ec433dfd970eec214657cfb5476c5d913366"
  end

  assert('Digest::HMAC#<<') do
    a = Digest::HMAC.new('hash key', Digest::SHA1)
    b = Digest::HMAC.new('hash key', Digest::SHA1)
    a.update('ruby')
    b << "r" << "u" << "b" << "y"
    a.hexdigest == b.hexdigest
  end

  assert('Digest::HMAC#block_length') do
    d = Digest::HMAC.new("hash key", Digest::SHA1)
    d.block_length == 64
  end

  assert('Digest::HMAC#digest_length') do
    d = Digest::HMAC.new("hash key", Digest::SHA1)
    d.digest_length == 20
  end

  # assert('Digest::HMAC#reset')

  assert('Digest::HMAC#update') do
    d = Digest::HMAC.new("hash key", Digest::SHA1)
    d.update('data')
    d.hexdigest == "fd20ec433dfd970eec214657cfb5476c5d913366"
  end

  assert('Digest::HMAC#update 2') do
    d = Digest::HMAC.new("hash key", Digest::SHA1)
    d.update('ruby')
    d.update('digest')
    d.hexdigest == "e4be3728777e43deba3aa522a4247ea83b19a1c7"
  end
end
