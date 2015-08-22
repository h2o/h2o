r = H2O::Request.new

url = "http://#{r.authority}/"

if r.uri == "/proxy.html"
  r.reverse_proxy "#{url}/proxy/"
end
