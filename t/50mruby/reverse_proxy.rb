r = H2O::Request.new

url = "http://#{r.authority}/"

if r.uri == "/proxy.html"
  r.reprocess_request "#{url}/proxy/"
end
