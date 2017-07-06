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
            f.ack()
            break
        else
            to_process << f
        end
    end
    to_process.each do |f|
        puts f.to_s
    end

    while true
        h2g.send_ping()
        f = h2g.read(-1)
        puts "type:#{f.type}, stream_id:#{f.stream_id}, len:#{f.len}, flags:#{f.flags}"
        if f.type == "GOAWAY" then
            puts f.to_s
            exit
        elsif f.type == "PING" then
            if f.flags & 1 == 0
              f.ack()
            end
        elsif f.type == "SETTINGS" then
            f.ack()
        end
        sleep 1
    end
rescue => e
    p e
end
