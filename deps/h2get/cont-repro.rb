begin
    to_process = []
    h2g = H2.new
    host = ARGV[0] || "www.fastly.com"
    puts "#######################"
    puts "# #{host}"
    puts "#######################"
    h2g.connect(host)
    h2g.send_prefix()
    h2g.send_settings()
    open_streams = {}
    # Ack settings
    while true do
        f = h2g.read(-1)
        puts f.to_s
        if f.type == "SETTINGS" and (f.flags & 1 == 1) then
            next
        elsif f.type == "SETTINGS" then
            h2g.send_settings_ack()
            break
        else
            to_process << f
        end
    end
    to_process.each do |f|
        puts f.to_s
    end

    req = {
        ":method" => "GET",
        ":authority" => host,
        ":scheme" => "https",
        ":path" => "/?1",
    }
    h2g.send_header(req, 15, 0)
    h2g.send_continuation({"x-test" => "1"}, 15, END_STREAM | END_HEADERS)

    open_streams[15] = 1
    while open_streams.length > 0
        f = h2g.read(-1)
        puts "type:#{f.type}, stream_id:#{f.stream_id}, len:#{f.len}, flags:#{f.flags}"
        if f.type == "GOAWAY" then
            puts f.to_s
        elsif f.type == "PING" then
            f.ack()
        elsif f.type == "SETTINGS" then
            puts f.to_s
        elsif f.type == "DATA" and f.len > 0 then
            h2g.send_window_update(0, f.len)
            h2g.send_window_update(f.stream_id, f.len)
        elsif f.type == "HEADERS" then
            puts f.to_s
        end

        if f.type == "DATA" or f.type == "HEADERS" then
            if f.is_end_stream
                open_streams.delete(f.stream_id)
            end
        end
    end
rescue => e
    p e
    exit 1
end
