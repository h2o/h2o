require 'time'
# require 'date'

class Time #:nodoc:
  class << self
    def mock_time
      mocked_time_stack_item = Timecop.top_stack_item
      mocked_time_stack_item.nil? ? nil : mocked_time_stack_item.time(self)
    end

    alias_method :now_without_mock_time, :now

    def now_with_mock_time
      mock_time || now_without_mock_time
    end

    alias_method :now, :now_with_mock_time

    alias_method :new_without_mock_time, :new

    def new_with_mock_time(*args)
      args.size <= 0 ? now : new_without_mock_time(*args)
    end

    alias_method :new, :new_with_mock_time
  end
end

# class Date #:nodoc:
#   WEEKDAYS = {
#     "sunday"    => 0,
#     "monday"    => 1,
#     "tuesday"   => 2,
#     "wednesday" => 3,
#     "thursday"  => 4,
#     "friday"    => 5,
#     "saturday"  => 6
#   }
# 
#   class << self
#     def mock_date
#       mocked_time_stack_item = Timecop.top_stack_item
#       mocked_time_stack_item.nil? ? nil : mocked_time_stack_item.date(self)
#     end
# 
#     alias_method :today_without_mock_date, :today
# 
#     def today_with_mock_date
#       mock_date || today_without_mock_date
#     end
# 
#     alias_method :today, :today_with_mock_date
# 
#     alias_method :strptime_without_mock_date, :strptime
# 
#     def strptime_with_mock_date(str = '-4712-01-01', fmt = '%F', start = Date::ITALY)
#       unless start == Date::ITALY
#         raise ArgumentError, "Timecop's #{self}::#{__method__} only " +
#           "supports Date::ITALY for the start argument."
#       end
# 
#       Time.strptime(str, fmt).to_date
#     end
# 
#     alias_method :strptime, :strptime_with_mock_date
# 
#     def parse_with_mock_date(*args)
#       str = args.first
#       if str.respond_to?(:downcase) && WEEKDAYS.keys.include?(str.downcase)
#         offset = WEEKDAYS[str.downcase] - Date.today.wday
# 
#         Date.today + offset
#       else
#         parse_without_mock_date(*args)
#       end
#     end
# 
#     alias_method :parse_without_mock_date, :parse
#     alias_method :parse, :parse_with_mock_date
# 
#   end
# end

# class DateTime #:nodoc:
#   class << self
#     def mock_time
#       mocked_time_stack_item = Timecop.top_stack_item
#       mocked_time_stack_item.nil? ? nil : mocked_time_stack_item.datetime(self)
#     end
# 
#     def now_with_mock_time
#       mock_time || now_without_mock_time
#     end
# 
#     alias_method :now_without_mock_time, :now
# 
#     alias_method :now, :now_with_mock_time
# 
#     def parse_with_mock_date(*args)
#       str = args.first
#       if str.respond_to?(:downcase) && Date::WEEKDAYS.keys.include?(str.downcase)
#         offset = Date::WEEKDAYS[str.downcase] - DateTime.now.wday
# 
#         parsed_weekday =(DateTime.now + offset)
# 
#         DateTime.new(parsed_weekday.year, parsed_weekday.month, parsed_weekday.day, 0, 0, 0, 0)
#       else
#         parse_without_mock_date(*args)
#       end
#     end
# 
#     alias_method :parse_without_mock_date, :parse
#     alias_method :parse, :parse_with_mock_date
#   end
# end
