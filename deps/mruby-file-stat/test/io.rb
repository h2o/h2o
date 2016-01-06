assert 'IO#stat' do
  # You can use IO#stat if implemented to IO#fileno
  # mruby-file-stat is just not implemented this.
  assert_raise(NotImplementedError) do
    IO.new(1).stat
  end
end
