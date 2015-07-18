r = H2O::Request.new

ua = r.headers_in["User-Agent"]

r.headers_in["User-Agent"] = "new-#{ua}"


r.headers_in["User-Agent"]
