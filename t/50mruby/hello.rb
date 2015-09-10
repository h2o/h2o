Proc.new do |env|
  [200, {"content-type" => "text/plain; charset=utf-8"}, ["hello from h2o_mruby\n"]]
end
