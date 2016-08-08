require 'misc/mruby-mtest/mrblib/mtest_unit.rb'
require 'share/h2o/mruby/acl.rb'

class ACLTest < MTest::Unit::TestCase
    include H2O::ACL
    def setup
        $ACL = 0
    end
    def teardown
        $ACL = nil
    end

    def test_use
        act = acl {
            use proc {|env| [200, {}, ["hello test_use"]]}
        }.call({})
        assert_equal([200, {}, ["hello test_use"]], act)
    end

    def test_response
        act = acl {
            response(409, {"custom" => "header"}, ["Conflict"])
        }.call({})
        assert_equal([409, {"custom" => "header"}, ["Conflict"]], act)
    end

    def test_deny
        act = acl {
            deny
        }.call({})
        assert_equal([403, {}, ["Forbidden"]], act)
    end

    def test_allow
        act = acl {
            allow
        }.call({})
        assert_equal([399, {}, []], act)
    end

    def test_redirect
        act = acl {
            redirect("https://h2o.examp1e.net/", 301)
        }.call({})
        assert_equal([301, {"Location" => "https://h2o.examp1e.net/"}, []], act)
    end

    ##### tests for condition block

    def test_conditional_true
        act = acl {
            response(200) { true }
        }.call({})
        assert_equal([200, {}, []], act)
    end

    def test_conditional_false
        act = acl {
            response(200) { false }
        }.call({})
        assert_equal([399, {}, []], act)
    end

    ##### tests for acl block

    def test_empty
        act = acl {
        }.call({})[0]
        assert_equal(399, act)
    end

    def test_multiple1
        act = acl {
            response(201) { true }
            response(202) { true }
        }.call({})[0]
        assert_equal(201, act)
    end

    def test_multiple2
        act = acl {
            response(201) { false }
            response(202) { true }
        }.call({})[0]
        assert_equal(202, act)
    end

    def test_multiple3
        act = acl {
            response(201) { false }
            response(202) { false }
        }.call({})[0]
        assert_equal(399, act)
    end

    def test_with_return_value1
        act = acl {
            response(200) { true }
            proc {|env| [404, {}, []]}
        }.call({})[0]
        assert_equal(200, act)
    end

    def test_with_return_value2
        act = acl {
            response(200) { false }
            proc {|env| [404, {}, []]}
        }.call({})[0]
        assert_equal(404, act)
    end

    def test_with_return_value3
        act = acl {
            proc {|env| [404, {}, []]}
            response(200) { true }
        }.call({})[0]
        assert_equal(200, act, "Of course ignored")
    end

    def test_with_return_value4
        act = acl {
            p = proc {|env| [404, {}, []]}
            response(200) { true }
            p
        }.call({})[0]
        assert_equal(200, act, "not ignored, but response(200) matches condition")
    end

    def test_with_return_value5
        act = acl {
            p = proc {|env| [404, {}, []]}
            response(200) { false }
            p
        }.call({})[0]
        assert_equal(404, act, "response(200) doesn't matches condition, so return value used")
    end


    ##### tests for matcher

    def test_addr
        handler = acl {
            response(200) { addr.match(/^192\.168\./) }
            response(403) { addr.match(/^200\./) }
            response(503) { addr.match(/^201\./) }
        }
        assert_equal(200, handler.call({ "REMOTE_ADDR" => "192.168.0.1"})[0])
        assert_equal(403, handler.call({ "REMOTE_ADDR" => "200.0.0.1"})[0])
        assert_equal(503, handler.call({ "REMOTE_ADDR" => "201.0.0.1"})[0])
        assert_equal(399, handler.call({ "REMOTE_ADDR" => "127.0.0.1"})[0])
        assert_equal(200, handler.call({ "HTTP_X_FORWARDED_FOR" => "192.168.0.1"})[0])
    end

    def test_addr_not_forwarded
        handler = acl {
            response(200) { addr(false).match(/^192\.168\./) }
            response(403)
        }
        assert_equal(200, handler.call({ "REMOTE_ADDR" => "192.168.0.1"})[0])
        assert_equal(403, handler.call({ "HTTP_X_FORWARDED_FOR" => "192.168.0.1"})[0])
    end

    def test_path
        handler = acl {
            response(200) { path == "/foo" }
            response(404)
        }
        assert_equal(200, handler.call({ "PATH_INFO" => "/foo"})[0])
        assert_equal(404, handler.call({ "PATH_INFO" => "/bar"})[0])
    end

    def test_method
        handler = acl {
            allow { method.match(/^(GET|HEAD)$/) }
            response(405)
        }
        assert_equal(399, handler.call({ "REQUEST_METHOD" => "GET"})[0])
        assert_equal(405, handler.call({ "REQUEST_METHOD" => "POST"})[0])
    end

    def test_method
        handler = acl {
            allow { method.match(/^(GET|HEAD)$/) }
            response(405)
        }
        assert_equal(399, handler.call({ "REQUEST_METHOD" => "GET"})[0])
        assert_equal(405, handler.call({ "REQUEST_METHOD" => "POST"})[0])
    end

    def test_header
        handler = acl {
            response(400, {}, ["authorization header missing"]) { header("Authorization").empty? }
        }
        assert_equal(400, handler.call({})[0])
        assert_equal(399, handler.call({ "HTTP_AUTHORIZATION" => "Bearer xyz"})[0])
    end

    def test_user_agent
        handler = acl {
            response(200, {}, ["hello googlebot!"]) { user_agent.match(/Googlebot/i) }
        }
        assert_equal(200, handler.call({ "HTTP_USER_AGENT" => "i'm Googlebot"})[0])
        assert_equal(399, handler.call({})[0])
    end

    def test_multiple_matchers
        handler = acl {
            response(403, {}, []) { ! addr.start_with?("192.168.") && user_agent.match(/curl/i) }
        }
        assert_equal(399, handler.call({ "REMOTE_ADDR" => "192.168.100.100", "HTTP_USER_AGENT" => "i'm firefox"})[0])
        assert_equal(399, handler.call({ "REMOTE_ADDR" => "192.168.100.100", "HTTP_USER_AGENT" => "i'm curl"})[0])
        assert_equal(399, handler.call({ "REMOTE_ADDR" => "222.222.222.222", "HTTP_USER_AGENT" => "i'm firefox"})[0])
        assert_equal(403, handler.call({ "REMOTE_ADDR" => "222.222.222.222", "HTTP_USER_AGENT" => "i'm curl"})[0])
    end
end

MTest::Unit.new.run
