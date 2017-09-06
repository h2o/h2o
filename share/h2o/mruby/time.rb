class Time
  DAY_NAME = [
    'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'
  ]

  MONTH_NAME = [
    '',
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
  ]
  MONTH_NUMBER = MONTH_NAME.map.with_index {|m, i| [m, i]}.to_h

  class << self

    # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
    def imf_fixdate(value)
      if value =~ /\A
          (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\x20
          (\d{1,2})\x20
          (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\x20
          (\d{4})\x20
          (\d{2}):(\d{2}):(\d{2})\x20
          GMT\Z/ix
        day = $1.to_i
        mon = MONTH_NUMBER[$2]
        year = $3.to_i
        hour = $4.to_i
        min = $5.to_i
        sec = $6.to_i
        self.utc(year, mon, day, hour, min, sec)
      else
        raise ArgumentError.new("not IMF-fixdate compliant date: #{value.inspect}")
      end
    end
  end


  def imf_fixdate
    t = dup.utc
    sprintf('%s, %02d %s %04d %02d:%02d:%02d GMT',
      DAY_NAME[t.wday], t.day, MONTH_NAME[t.mon], t.year, t.hour, t.min, t.sec)
  end
end
