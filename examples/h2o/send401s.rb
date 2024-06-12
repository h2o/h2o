STDOUT.sync = true
h2g = H2.server({
    'cert_path' => '/fst-h2o/examples/h2o/server.crt',
    'key_path' => '/fst-h2o/examples/h2o/server.key',
});
h2g.listen("https://127.0.0.1:1443")

loop do
  conn = h2g.accept(-1)
  puts "recv conn = #{conn}"

  conn.expect_prefix
  conn.send_settings([])

  loop do
    f = conn.read(-1)
    puts "recv f = #{f}"
    if f.type == 'SETTINGS'
      unless f.flags == ACK then
        conn.send_settings_ack()
        break
      end
    else
      raise 'oops'
    end
  end

  f = nil
  loop do
    f = conn.read(-1)
    puts "recv f = #{f}"
    if f.type == 'HEADERS'
      break
    end
  end
  puts "stream_id = #{f.stream_id}"
  resp = {
        ":status" => "401",
        "hello" => "world",
  }
  conn.send_headers(resp, f.stream_id, END_HEADERS | END_STREAM)
  # sleep(5);
  conn.send_rst_stream(f.stream_id, 5)

end
