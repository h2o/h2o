class File
  def self.stat(fname)
    File::Stat.new(fname)
  end
end
