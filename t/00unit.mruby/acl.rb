$LOAD_PATH << 'share/h2o/mruby'
require 'misc/mruby-mtest/mrblib/mtest_unit.rb'
require 'acl.rb'

class ACLTest < MTest::Unit::TestCase
    include H2O::ACL
    def setup
        H2O::ConfigurationContext.reset
    end

    def test_use
        act = acl {
            use proc {|env| [200, {}, ["hello test_use"]]}
        }.call({})
        assert_equal([200, {}, ["hello test_use"]], act)
    end

    def test_respond
        act = acl {
            respond(409, {"custom" => "header"}, ["Conflict"])
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
            respond(200) { true }
        }.call({})
        assert_equal([200, {}, []], act)
    end

    def test_conditional_false
        act = acl {
            respond(200) { false }
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
            respond(201) { true }
            respond(202) { true }
        }.call({})[0]
        assert_equal(201, act)
    end

    def test_multiple2
        act = acl {
            respond(201) { false }
            respond(202) { true }
        }.call({})[0]
        assert_equal(202, act)
    end

    def test_multiple3
        act = acl {
            respond(201) { false }
            respond(202) { false }
        }.call({})[0]
        assert_equal(399, act)
    end

    def test_acl_restriction1
        acl { respond(200) }
        assert_raise(RuntimeError, "must raise exception if acl method is called more than once") {
            acl { respond(200) }
        }
    end

    ##### tests for matcher

    def test_addr
        handler = acl {
            respond(200) { addr.match(/^192\.168\./) }
            respond(403) { addr.match(/^200\./) }
            respond(503) { addr.match(/^201\./) }
        }
        assert_equal(200, handler.call({ "REMOTE_ADDR" => "192.168.0.1"})[0])
        assert_equal(403, handler.call({ "REMOTE_ADDR" => "200.0.0.1"})[0])
        assert_equal(503, handler.call({ "REMOTE_ADDR" => "201.0.0.1"})[0])
        assert_equal(399, handler.call({ "REMOTE_ADDR" => "127.0.0.1"})[0])
        assert_equal(200, handler.call({ "HTTP_X_FORWARDED_FOR" => "192.168.0.1"})[0])
    end

    def test_addr_not_forwarded
        handler = acl {
            respond(200) { addr(false).match(/^192\.168\./) }
            respond(403)
        }
        assert_equal(200, handler.call({ "REMOTE_ADDR" => "192.168.0.1"})[0])
        assert_equal(403, handler.call({ "HTTP_X_FORWARDED_FOR" => "192.168.0.1"})[0])
    end

    def test_path
        handler = acl {
            respond(200) { path == "/foo" }
            respond(404)
        }
        assert_equal(200, handler.call({ "PATH_INFO" => "/foo"})[0])
        assert_equal(404, handler.call({ "PATH_INFO" => "/bar"})[0])
    end

    def test_method
        handler = acl {
            allow { method.match(/^(GET|HEAD)$/) }
            respond(405)
        }
        assert_equal(399, handler.call({ "REQUEST_METHOD" => "GET"})[0])
        assert_equal(405, handler.call({ "REQUEST_METHOD" => "POST"})[0])
    end

    def test_method
        handler = acl {
            allow { method.match(/^(GET|HEAD)$/) }
            respond(405)
        }
        assert_equal(399, handler.call({ "REQUEST_METHOD" => "GET"})[0])
        assert_equal(405, handler.call({ "REQUEST_METHOD" => "POST"})[0])
    end

    def test_header
        handler = acl {
            respond(400, {}, ["authorization header missing"]) { header("Authorization").empty? }
        }
        assert_equal(400, handler.call({})[0])
        assert_equal(399, handler.call({ "HTTP_AUTHORIZATION" => "Bearer xyz"})[0])
    end

    def test_user_agent
        handler = acl {
            respond(200, {}, ["hello googlebot!"]) { user_agent.match(/Googlebot/i) }
        }
        assert_equal(200, handler.call({ "HTTP_USER_AGENT" => "i'm Googlebot"})[0])
        assert_equal(399, handler.call({})[0])
    end

    def test_multiple_matchers
        handler = acl {
            respond(403, {}, []) { ! addr.start_with?("192.168.") && user_agent.match(/curl/i) }
        }
        assert_equal(399, handler.call({ "REMOTE_ADDR" => "192.168.100.100", "HTTP_USER_AGENT" => "i'm firefox"})[0])
        assert_equal(399, handler.call({ "REMOTE_ADDR" => "192.168.100.100", "HTTP_USER_AGENT" => "i'm curl"})[0])
        assert_equal(399, handler.call({ "REMOTE_ADDR" => "222.222.222.222", "HTTP_USER_AGENT" => "i'm firefox"})[0])
        assert_equal(403, handler.call({ "REMOTE_ADDR" => "222.222.222.222", "HTTP_USER_AGENT" => "i'm curl"})[0])
    end
end

MTest::Unit.new.run
