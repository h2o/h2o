begin
    h2g = H2.new
    host = ARGV[0] || "www.fastly.com"
    puts "connecting to #{host}"
    h2g.connect(host)
    h2g.send_prefix()
    h2g.send_settings([[2,0]])
    open_streams = {}
    # Ack settings
    while true do
        f = h2g.read(-1)
        puts f.to_s
        puts f.payload.bytes
    end
    h2g.close()
    h2g.destroy()
rescue => e
    p e
    exit 1
end
