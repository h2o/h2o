##
# Time ISO Test

assert('Time.new', '15.2.3.3.3') do
  assert_equal(Time, Time.new.class)
end

assert('Time', '15.2.19') do
  assert_equal(Class, Time.class)
end

assert('Time.at', '15.2.19.6.1') do
  assert_kind_of(Time, Time.at(1300000000.0))

  skip unless Object.const_defined?(:Float)
  assert_raise(FloatDomainError) { Time.at(Float::NAN) }
  assert_raise(FloatDomainError) { Time.at(Float::INFINITY) }
  assert_raise(FloatDomainError) { Time.at(-Float::INFINITY) }
  assert_raise(FloatDomainError) { Time.at(0, Float::NAN) }
  assert_raise(FloatDomainError) { Time.at(0, Float::INFINITY) }
  assert_raise(FloatDomainError) { Time.at(0, -Float::INFINITY) }
end

assert('Time.gm', '15.2.19.6.2') do
  t = Time.gm(2012, 9, 23)
  assert_operator(2012, :eql?, t.year)
  assert_operator(   9, :eql?, t.month)
  assert_operator(  23, :eql?, t.day)
  assert_operator(   0, :eql?, t.hour)
  assert_operator(   0, :eql?, t.min)
  assert_operator(   0, :eql?, t.sec)
  assert_operator(   0, :eql?, t.usec)
end

assert('Time.local', '15.2.19.6.3') do
  t = Time.local(2014, 12, 27, 18)
  assert_operator(2014, :eql?, t.year)
  assert_operator(  12, :eql?, t.month)
  assert_operator(  27, :eql?, t.day)
  assert_operator(  18, :eql?, t.hour)
  assert_operator(   0, :eql?, t.min)
  assert_operator(   0, :eql?, t.sec)
  assert_operator(   0, :eql?, t.usec)
end

assert('Time.mktime', '15.2.19.6.4') do
  t = Time.mktime(2013, 10, 4, 6, 15, 58, 3485)
  assert_operator(2013, :eql?, t.year)
  assert_operator(  10, :eql?, t.month)
  assert_operator(   4, :eql?, t.day)
  assert_operator(   6, :eql?, t.hour)
  assert_operator(  15, :eql?, t.min)
  assert_operator(  58, :eql?, t.sec)
  assert_operator(3485, :eql?, t.usec)
end

assert('Time.now', '15.2.19.6.5') do
  assert_equal(Time, Time.now.class)
end

assert('Time.utc', '15.2.19.6.6') do
  t = Time.utc(2034)
  assert_operator(2034, :eql?, t.year)
  assert_operator(   1, :eql?, t.month)
  assert_operator(   1, :eql?, t.day)
  assert_operator(   0, :eql?, t.hour)
  assert_operator(   0, :eql?, t.min)
  assert_operator(   0, :eql?, t.sec)
  assert_operator(   0, :eql?, t.usec)
end

assert('Time#+', '15.2.19.7.1') do
  t1 = Time.at(1300000000)
  t2 = t1.+(60)

  assert_equal("Sun Mar 13 07:07:40 2011", t2.utc.asctime)

  skip unless Object.const_defined?(:Float)
  assert_raise(FloatDomainError) { Time.at(0) + Float::NAN }
  assert_raise(FloatDomainError) { Time.at(0) + Float::INFINITY }
  assert_raise(FloatDomainError) { Time.at(0) + -Float::INFINITY }
end

assert('Time#-', '15.2.19.7.2') do
  t1 = Time.at(1300000000)
  t2 = t1.-(60)

  assert_equal("Sun Mar 13 07:05:40 2011", t2.utc.asctime)

  skip unless Object.const_defined?(:Float)
  assert_raise(FloatDomainError) { Time.at(0) - Float::NAN }
  assert_raise(FloatDomainError) { Time.at(0) - Float::INFINITY }
  assert_raise(FloatDomainError) { Time.at(0) - -Float::INFINITY }
end

assert('Time#<=>', '15.2.19.7.3') do
  t1 = Time.at(1300000000)
  t2 = Time.at(1400000000)
  t3 = Time.at(1500000000)

  assert_equal(1, t2 <=> t1)
  assert_equal(0, t2 <=> t2)
  assert_equal(-1, t2 <=> t3)
  assert_nil(t2 <=> nil)
end

assert('Time#asctime', '15.2.19.7.4') do
  assert_equal("Thu Mar  4 05:06:07 1982", Time.gm(1982,3,4,5,6,7).asctime)
end

assert('Time#ctime', '15.2.19.7.5') do
  assert_equal("Thu Oct 24 15:26:47 2013", Time.gm(2013,10,24,15,26,47).ctime)
end

assert('Time#day', '15.2.19.7.6') do
  assert_equal(23, Time.gm(2012, 12, 23).day)
end

assert('Time#dst?', '15.2.19.7.7') do
  assert_not_predicate(Time.gm(2012, 12, 23).utc, :dst?)
end

assert('Time#getgm', '15.2.19.7.8') do
  assert_equal("Sun Mar 13 07:06:40 2011", Time.at(1300000000).getgm.asctime)
end

assert('Time#getlocal', '15.2.19.7.9') do
  t1 = Time.at(1300000000.0)
  t2 = Time.at(1300000000.0)
  t3 = t1.getlocal

  assert_equal(t1, t3)
  assert_equal(t3, t2.getlocal)
end

assert('Time#getutc', '15.2.19.7.10') do
  assert_equal("Sun Mar 13 07:06:40 2011", Time.at(1300000000).getutc.asctime)
end

assert('Time#gmt?', '15.2.19.7.11') do
  assert_predicate(Time.at(1300000000).utc, :gmt?)
end

# ATM not implemented
# assert('Time#gmt_offset', '15.2.19.7.12') do

assert('Time#gmtime', '15.2.19.7.13') do
  t = Time.now
  assert_predicate(t.gmtime, :gmt?)
  assert_predicate(t, :gmt?)
end

# ATM not implemented
# assert('Time#gmtoff', '15.2.19.7.14') do

assert('Time#hour', '15.2.19.7.15') do
  assert_equal(7, Time.gm(2012, 12, 23, 7, 6).hour)
end

# ATM doesn't really work
# assert('Time#initialize', '15.2.19.7.16') do

assert('Time#initialize_copy', '15.2.19.7.17') do
  t = Time.at(7.0e6)
  assert_equal(t, t.clone)
end

assert('Time#localtime', '15.2.19.7.18') do
  t1 = Time.utc(2014, 5 ,6)
  t2 = Time.utc(2014, 5 ,6)
  t3 = t2.getlocal

  assert_equal(t3, t1.localtime)
  assert_equal(t3, t1)
end

assert('Time#mday', '15.2.19.7.19') do
  assert_equal(23, Time.gm(2012, 12, 23).mday)
end

assert('Time#min', '15.2.19.7.20') do
  assert_equal(6, Time.gm(2012, 12, 23, 7, 6).min)
end

assert('Time#mon', '15.2.19.7.21') do
  assert_equal(12, Time.gm(2012, 12, 23).mon)
end

assert('Time#month', '15.2.19.7.22') do
  assert_equal(12, Time.gm(2012, 12, 23).month)
end

assert('Times#sec', '15.2.19.7.23') do
  assert_equal(40, Time.gm(2012, 12, 23, 7, 6, 40).sec)
end

assert('Time#to_f', '15.2.19.7.24') do
  skip unless Object.const_defined?(:Float)
  assert_operator(2.0, :eql?, Time.at(2).to_f)
end

assert('Time#to_i', '15.2.19.7.25') do
  assert_operator(2, :eql?, Time.at(2).to_i)
end

assert('Time#usec', '15.2.19.7.26') do
  assert_equal(0, Time.at(1300000000).usec)
  skip unless Object.const_defined?(:Float)
  assert_equal(0, Time.at(1300000000.0).usec)
end

assert('Time#utc', '15.2.19.7.27') do
  t = Time.now
  assert_predicate(t.utc, :gmt?)
  assert_predicate(t, :gmt?)
end

assert('Time#utc?', '15.2.19.7.28') do
  assert_predicate(Time.at(1300000000).utc, :utc?)
end

# ATM not implemented
# assert('Time#utc_offset', '15.2.19.7.29') do

assert('Time#wday', '15.2.19.7.30') do
  assert_equal(0, Time.gm(2012, 12, 23).wday)
end

assert('Time#yday', '15.2.19.7.31') do
  assert_equal(358, Time.gm(2012, 12, 23).yday)
end

assert('Time#year', '15.2.19.7.32') do
  assert_equal(2012, Time.gm(2012, 12, 23).year)
end

assert('Time#zone', '15.2.19.7.33') do
  assert_equal('UTC', Time.at(1300000000).utc.zone)
end

# Not ISO specified

assert('Time#to_s') do
  assert_equal("2003-04-05 06:07:08 UTC", Time.gm(2003,4,5,6,7,8,9).to_s)
end

assert('Time#inspect') do
  assert_match("2013-10-28 16:27:48 [+-][0-9][0-9][0-9][0-9]",
               Time.local(2013,10,28,16,27,48).inspect)
end

assert('day of week methods') do
  t = Time.gm(2012, 12, 24)
  assert_false t.sunday?
  assert_true t.monday?
  assert_false t.tuesday?
  assert_false t.wednesday?
  assert_false t.thursday?
  assert_false t.friday?
  assert_false t.saturday?
end

assert('2000 times 500us make a second') do
  t = Time.utc 2015
  2000.times do
    t += 0.0005
  end
  assert_equal(0, t.usec)
end
