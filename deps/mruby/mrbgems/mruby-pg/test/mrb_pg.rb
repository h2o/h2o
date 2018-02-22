# Before run this test case, You should run following commands.
# $ dropdb mrb_pg_test
# $ createdb -e mrb_pg_test

HOST = nil # using Unix domain socket (trusted)
PORT = 5432
DBNAME = 'mrb_pg_test'
CONNINFO = ""
CONNINFO += "host=#{HOST}" if not HOST.nil?
CONNINFO += "port=#{PORT} dbname=#{DBNAME}"

assert('PG::Connection.new') do
  begin
    PG::Connection.new(host: "invalid", port: 90)
    break false
  rescue PG::Error
    true
  end
end

assert('PG::Connection.new', 'should establish a connection') do
  @conn = PG::Connection.new(CONNINFO)
  assert_false @conn.nil?
end

assert('PG::Connection#exec') do
  @conn.exec("drop table if exists test;")
  @conn.exec("create table test (id int, name varchar(256));")
  @conn.exec("insert into test (id, name) VALUES (1, 'test');")
  res = @conn.exec("select * from test;")
  assert_false res.check.nil?
end

assert('PG::Connection#exec with block') do
  @conn.exec("select * from test;") do |result|
    assert_equal "1", result["id"]
    assert_equal "test", result["name"]
  end
end

assert('PG::Connection#exec with params') do
  @conn.exec("select * from test where id = $1", [1]) do |result|
    assert_equal "1", result["id"]
    assert_equal "test", result["name"]
  end
end

assert('PG::Connection#exec_params') do
  @conn.exec_params("INSERT INTO test VALUES( $1, $2 )", [2, 'bob'])
  @conn.exec_params("select * from test where id = $1", [2], 0) do |result|
    assert_equal "2", result["id"]
    assert_equal "bob", result["name"]
  end
end

assert('PG::Connection#transaction') do
  @conn.transaction do
    @conn.exec("INSERT INTO test VALUES( $1, $2 )", [3, "jon"])
  end
  assert_equal "jon", @conn.exec("select * from test where id = $1", [3]).first["name"]
  begin
    @conn.transaction do
      @conn.exec("INSERT INTO test VALUES( $1, $2 )", [4, "aaron"])
      raise "unexpected error"
    end
  rescue
  end
  assert_equal 0, @conn.exec("select * from test where id = $1", [4]).size
end

