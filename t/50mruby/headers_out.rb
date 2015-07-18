r = H2O::Request.new

r.headers_out["new-header"] = "h2o-mruby"

# pass to next handler
nil
