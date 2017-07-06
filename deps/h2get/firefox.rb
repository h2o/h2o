begin
    to_process = []
    h2g = H2.new
    host = ARGV[0] || "www.fastly.com"
    puts "#######################"
    puts "# #{host}"
    puts "#######################"
    h2g.connect(host)
    h2g.send_prefix()
    h2g.send_settings([[2,0]])
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

    h2g.send_priority(3, 0, 1, 201)
    h2g.send_priority(5, 0, 0, 101)
    h2g.send_priority(7, 0, 0, 1)
    h2g.send_priority(9, 7, 0, 1)
    h2g.send_priority(11, 3, 0, 1)
    prio_low = H2Priority.new(0, 0, 16)
    prio_high = H2Priority.new(0, 0, 32)
    req = {
        ":method" => "GET",
        ":authority" => host,
        ":scheme" => "https",
    }
    req1 = req.merge(":path" => "/?1")
    req2 = req.merge(":path" => "/?2")
    h2g.send_headers(req1, 15, PRIORITY | END_STREAM, prio_low)
    h2g.send_continuation({}, 15, END_HEADERS)
    h2g.send_headers(req2, 17, 37, prio_low)
    open_streams[15] = 1
    open_streams[17] = 1
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
    h2g.close()
    h2g.destroy()
rescue => e
    p e
    exit 1
end
