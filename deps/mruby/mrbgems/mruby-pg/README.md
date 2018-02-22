# mruby-pg

Mini PostgreSQL binding for mruby.

## Usage

```ruby
# Establish connectoin
@conn = PG::Connection.new(port: 5432, dbname: "test")

# Send SQL
@conn.exec("CREATE TABLE students (id INT, name VARCHAR(256))")
@conn.exec("INSERT INTO students VALUES($1, $2)", [1, 'bob'])
@conn.exec("SELECT * FROM students") do |result|
  puts result["id"]   # => "1"
  puts result["name"] # => "bob"
end

# Transaction
@conn.transaction do
  @conn.exec("INSERT INTO students VALUES($1, $2)", [2, 'jon'])
end
```

## Thanks

This mgem is mini ruby-pg. Thank you, ruby-pg developers.
https://bitbucket.org/ged/ruby-pg/wiki/Home
