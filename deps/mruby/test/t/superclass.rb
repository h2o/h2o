[
  # [:Object, :implementation_defined_value, '15.2.2.1'],
  [:Module, :Object, '15.2.2.2'],
  [:Class, :Module, '15.2.3.2'],
  [:NilClass, :Object, '15.2.4.2'],
  [:TrueClass, :Object, '15.2.5.2'],
  [:FalseClass, :Object, '15.2.6.2'],
  [:Numeric, :Object, '15.2.7.2'],
  [:Integer, :Numeric, '15.2.8.2'],
  [:Float, :Numeric, '15.2.9.2'],
  [:String, :Object, '15.2.10.2'],
  [:Symbol, :Object, '15.2.11.2'],
  [:Array, :Object, '15.2.12.2'],
  [:Hash, :Object, '15.2.13.2'],
  [:Range, :Object, '15.2.14.2'],
#  [:Regexp, :Object, '15.2.15.2'],      #No Regexp in mruby core
#  [:MatchData, :Object, '15.2.16.2'],
  [:Proc, :Object, '15.2.17.2'],
#  [:Struct, :Object, '15.2.18.2'],
#  [:Time, :Object, '15.2.19.2'],
#  [:IO, :Object, '15.2.20.2'],
#  [:File, :IO, '15.2.21.2'],
  [:Exception, :Object, '15.2.22.2'],
  [:StandardError, :Exception, '15.2.23.2'],
  [:ArgumentError, :StandardError, '15.2.24.2'],
  # [:LocalJumpError, :StandardError, '15.2.25.2'],
  [:LocalJumpError, :ScriptError, '15.2.25.2'], # mruby specific
  [:RangeError, :StandardError, '12.2.26.2'],
  [:RegexpError, :StandardError, '12.2.27.2'],
  [:RuntimeError, :StandardError, '12.2.28.2'],
  [:TypeError, :StandardError, '12.2.29.2'],
#  [:ZeroDivisionError, :StandardError, '12.2.30.2'],  # No ZeroDivisionError in mruby
  [:NameError, :StandardError, '15.2.31.2'],
  [:NoMethodError, :NameError, '15.2.32.2'],
  [:IndexError, :StandardError, '15.2.33.2'],
#  [:IOError, :StandardError, '12.2.34.2'],
#  [:EOFError, :IOError, '12.2.35.2'],
#  [:SystemCallError, :StandardError, '15.2.36.2'],
  [:ScriptError, :Exception, '12.2.37.2'],
  [:SyntaxError, :ScriptError, '12.2.38.2'],
#  [:LoadError, :ScriptError, '12.2.39,2'],
].each do |cls, super_cls, iso|
  assert "Direct superclass of #{cls}", iso do
    skip "#{cls} isn't defined" unless Object.const_defined? cls
    assert_equal Object.const_get(super_cls), Object.const_get(cls).superclass
  end
end
