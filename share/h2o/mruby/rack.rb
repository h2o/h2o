module Rack
  HTTP_HOST         = 'HTTP_HOST'.freeze
  HTTP_VERSION      = 'HTTP_VERSION'.freeze
  HTTPS             = 'HTTPS'.freeze
  PATH_INFO         = 'PATH_INFO'.freeze
  REQUEST_METHOD    = 'REQUEST_METHOD'.freeze
  REQUEST_PATH      = 'REQUEST_PATH'.freeze
  SCRIPT_NAME       = 'SCRIPT_NAME'.freeze
  QUERY_STRING      = 'QUERY_STRING'.freeze
  SERVER_PROTOCOL   = 'SERVER_PROTOCOL'.freeze
  SERVER_NAME       = 'SERVER_NAME'.freeze
  SERVER_ADDR       = 'SERVER_ADDR'.freeze
  SERVER_PORT       = 'SERVER_PORT'.freeze
  CACHE_CONTROL     = 'Cache-Control'.freeze
  CONTENT_LENGTH    = 'Content-Length'.freeze
  CONTENT_TYPE      = 'Content-Type'.freeze
  SET_COOKIE        = 'Set-Cookie'.freeze
  TRANSFER_ENCODING = 'Transfer-Encoding'.freeze
  HTTP_COOKIE       = 'HTTP_COOKIE'.freeze
  ETAG              = 'ETag'.freeze

  GET     = 'GET'.freeze
  POST    = 'POST'.freeze
  PUT     = 'PUT'.freeze
  PATCH   = 'PATCH'.freeze
  DELETE  = 'DELETE'.freeze
  HEAD    = 'HEAD'.freeze
  OPTIONS = 'OPTIONS'.freeze
  LINK    = 'LINK'.freeze
  UNLINK  = 'UNLINK'.freeze
  TRACE   = 'TRACE'.freeze

  RACK_VERSION                        = 'rack.version'.freeze
  RACK_TEMPFILES                      = 'rack.tempfiles'.freeze
  RACK_ERRORS                         = 'rack.errors'.freeze
  RACK_LOGGER                         = 'rack.logger'.freeze
  RACK_INPUT                          = 'rack.input'.freeze
  RACK_SESSION                        = 'rack.session'.freeze
  RACK_SESSION_OPTIONS                = 'rack.session.options'.freeze
  RACK_SHOWSTATUS_DETAIL              = 'rack.showstatus.detail'.freeze
  RACK_MULTITHREAD                    = 'rack.multithread'.freeze
  RACK_MULTIPROCESS                   = 'rack.multiprocess'.freeze
  RACK_RUNONCE                        = 'rack.run_once'.freeze
  RACK_URL_SCHEME                     = 'rack.url_scheme'.freeze
  RACK_HIJACK                         = 'rack.hijack'.freeze
  RACK_IS_HIJACK                      = 'rack.hijack?'.freeze
  RACK_HIJACK_IO                      = 'rack.hijack_io'.freeze
  RACK_RECURSIVE_INCLUDE              = 'rack.recursive.include'.freeze
  RACK_MULTIPART_BUFFER_SIZE          = 'rack.multipart.buffer_size'.freeze
  RACK_MULTIPART_TEMPFILE_FACTORY     = 'rack.multipart.tempfile_factory'.freeze
  RACK_REQUEST_FORM_INPUT             = 'rack.request.form_input'.freeze
  RACK_REQUEST_FORM_HASH              = 'rack.request.form_hash'.freeze
  RACK_REQUEST_FORM_VARS              = 'rack.request.form_vars'.freeze
  RACK_REQUEST_COOKIE_HASH            = 'rack.request.cookie_hash'.freeze
  RACK_REQUEST_COOKIE_STRING          = 'rack.request.cookie_string'.freeze
  RACK_REQUEST_QUERY_HASH             = 'rack.request.query_hash'.freeze
  RACK_REQUEST_QUERY_STRING           = 'rack.request.query_string'.freeze
  RACK_METHODOVERRIDE_ORIGINAL_METHOD = 'rack.methodoverride.original_method'.freeze
  RACK_SESSION_UNPACKED_COOKIE_DATA   = 'rack.session.unpacked_cookie_data'.freeze

  require 'rack/request'
end
