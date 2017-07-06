begin
    h2g = H2.new
    h2g.connect('https://www.google.com')
    h2g.send_prefix()
    h2g.send_settings()
    f = h2g.read(-1)
    puts f.to_s
    h2g.settings_ack()
    (1..2).each {
        h2g.get()
        f = h2g.read(-1)
        puts f.to_s
    }
    f = h2g.read(-1)
    puts f.to_s
rescue Exception => e
    h2g.close()
    puts e.message
    puts e.backtrace.inspect
end
puts "OK"
