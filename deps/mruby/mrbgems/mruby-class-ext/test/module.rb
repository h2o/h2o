assert 'Module#name' do
  module A
    class B
    end
  end

  assert_nil A::B.singleton_class.name
  assert_equal 'Fixnum', Fixnum.name
  assert_equal 'A::B', A::B.name
end
