host = ARGV[0]
host ||= "https://www.fastly.com"
begin
    h2g = H2.new
    h2g.connect(host)
    h2g.send_prefix()
    f = h2g.read(1000)
    puts(f.to_s)
    h2g.send_settings()

    loop do
        f = h2g.read(1000)
        break if f == nil
        puts("Received a #{f.type} frame")
        if f.type == "SETTINGS" then
            h2g.on_settings(f)
            h2g.send_settings_ack()
        else
            puts("Received a #{f.type} frame")
            exit 1
        end
    end
    h2g.send_window_update(0, 10000)

    puts("Sending get")
    h2g.get("/")
    h2g.send_window_update(1, 10000)
    loop do
        f = h2g.read(10000)
        break if f == nil
        puts("Received a #{f.type} frame")
        puts(f.to_s)
    end
    puts("Exiting")

rescue Exception => e
    h2g.close() if h2g != nil
    puts "Exception: #{e.message}"
    #p e.backtrace if e.backtrace.length != 0
end
