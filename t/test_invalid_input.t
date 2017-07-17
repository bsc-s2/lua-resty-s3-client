use Test::Nginx::Socket::Lua 'no_plan';


our $HttpConfig = qq{
    lua_package_path 'lib/?.lua;/usr/local/s2/current/nginx/conf/lua/?.lua;/usr/local/s2/current/nginx/conf/lua/dep/?.lua;;';
    lua_package_cpath 'lib/?.so;/usr/local/s2/current/nginx/conf/lua/lib/?.so;;';
};

no_long_string();
$ENV{TEST_NGINX_ACCESS_KEY} = '"ziw5dp1alvty9n47qksu"';
$ENV{TEST_NGINX_SECRET_KEY} = '"V+ZTZ5u5wNvXb+KP5g0dMNzhMeWe372/yRKx4hZV"';
$ENV{TEST_NGINX_ENDPOINT} = '"127.0.0.1"';
run_tests();

__DATA__

=== TEST 1: test invalid access_key

--- http_config eval: $::HttpConfig
--- config
location = /t {
    rewrite_by_lua_block {
        local s3_client = require('resty.aws_s3.client')
        local tableutil = require('acid.tableutil')
        local client, err, errmsg = s3_client.new(44, 44, '127.0.0.1')
        if err ~= nil then
            ngx.say(string.format('failed to new s3_client: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('new s3_client ok')
        end

        local resp, err, errmsg = s3_client:list_buckets()
        if err ~= nil then
            ngx.say(string.format('failed to list buckets: %s, %s', err ,errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('list buckets ok')
        end
    }
}
--- request
GET /t

--- timeout: 15
--- response_body_like chomp
failed to new s3_client: InvalidArgument, access_key: 44, is not a string


=== TEST 2: test params is nil

--- http_config eval: $::HttpConfig
--- config
location = /t {
    rewrite_by_lua_block {
        local s3_client = require('resty.aws_s3.client')
        local tableutil = require('acid.tableutil')
        local client, err, errmsg = s3_client.new($TEST_NGINX_ACCESS_KEY,
                                                  $TEST_NGINX_SECRET_KEY,
                                                  $TEST_NGINX_ENDPOINT)
        if err ~= nil then
            ngx.say(string.format('failed to new s3_client: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('new s3_client ok')
        end

        local resp, err, errmsg = client:create_bucket()
        if err ~= nil then
            ngx.say(string.format('failed to create bucket: %s, %s', err ,errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('create bucket ok')
        end
    }
}
--- request
GET /t

--- timeout: 15
--- response_body_like chomp
failed to create bucket: InvalidArgument.*


=== TEST 3: test invalid client_opts

--- http_config eval: $::HttpConfig
--- config
location = /t {
    rewrite_by_lua_block {
        local s3_client = require('resty.aws_s3.client')
        local tableutil = require('acid.tableutil')
        local client, err, errmsg = s3_client.new($TEST_NGINX_ACCESS_KEY,
                                                  $TEST_NGINX_SECRET_KEY,
                                                  $TEST_NGINX_ENDPOINT,
                                                  444)
        if err ~= nil then
            ngx.say(string.format('failed to new s3_client: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('new s3_client ok')
        end
    }
}
--- request
GET /t

--- timeout: 15
--- response_body_like chomp
failed to new s3_client: InvalidArgument, invalid client_opts: 444, is not a table, is type: number

=== TEST 4: test invalid opts

--- http_config eval: $::HttpConfig
--- config
location = /t {
    rewrite_by_lua_block {
        local s3_client = require('resty.aws_s3.client')
        local tableutil = require('acid.tableutil')
        local client, err, errmsg = s3_client.new($TEST_NGINX_ACCESS_KEY,
                                                  $TEST_NGINX_SECRET_KEY,
                                                  $TEST_NGINX_ENDPOINT)
        if err ~= nil then
            ngx.say(string.format('failed to new s3_client: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('new s3_client ok')
        end

        local resp, err, errmsg = client:create_bucket(
                {Bucket='test-bucket'}, 444)
        if err ~= nil then
            ngx.say(string.format('failed to create bucket: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('create bucket ok')
        end
    }
}
--- request
GET /t

--- timeout: 15
--- response_body_like chomp
failed to create bucket: InvalidArgument, invalid opts: 444, is not a table, is type: number


=== TEST 5: test invalid params

--- http_config eval: $::HttpConfig
--- config
location = /t {
    rewrite_by_lua_block {
        local s3_client = require('resty.aws_s3.client')
        local tableutil = require('acid.tableutil')
        local client, err, errmsg = s3_client.new($TEST_NGINX_ACCESS_KEY,
                                                  $TEST_NGINX_SECRET_KEY,
                                                  $TEST_NGINX_ENDPOINT)
        if err ~= nil then
            ngx.say(string.format('failed to new s3_client: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('new s3_client ok')
        end

        local resp, err, errmsg = client:create_bucket(444)
        if err ~= nil then
            ngx.say(string.format('failed to create bucket: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('create bucket ok')
        end
    }
}
--- request
GET /t

--- timeout: 15
--- response_body_like chomp
failed to create bucket: InvalidArgument, invalid params: 444, is not a table, is type: number


=== TEST 6: test invalid parameter

--- http_config eval: $::HttpConfig
--- config
location = /t {
    rewrite_by_lua_block {
        local s3_client = require('resty.aws_s3.client')
        local tableutil = require('acid.tableutil')
        local client, err, errmsg = s3_client.new($TEST_NGINX_ACCESS_KEY,
                                                  $TEST_NGINX_SECRET_KEY,
                                                  $TEST_NGINX_ENDPOINT)
        if err ~= nil then
            ngx.say(string.format('failed to new s3_client: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('new s3_client ok')
        end

        local resp, err, errmsg = client:create_bucket(
                {Bucket='test-bucket', foo='bar'})
        if err ~= nil then
            ngx.say(string.format('failed to create bucket: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('create bucket ok')
        end
    }
}
--- request
GET /t

--- timeout: 15
--- response_body_like chomp
failed to create bucket: InvalidArgument.*


=== TEST 7: test invalid acl

--- http_config eval: $::HttpConfig
--- config
location = /t {
    rewrite_by_lua_block {
        local s3_client = require('resty.aws_s3.client')
        local tableutil = require('acid.tableutil')
        local client, err, errmsg = s3_client.new($TEST_NGINX_ACCESS_KEY,
                                                  $TEST_NGINX_SECRET_KEY,
                                                  $TEST_NGINX_ENDPOINT)
        if err ~= nil then
            ngx.say(string.format('failed to new s3_client: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('new s3_client ok')
        end

        local resp, err, errmsg = client:create_bucket(
                {Bucket='test-bucket', ACL='foo'})
        if err ~= nil then
            ngx.say(string.format('failed to create bucket: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('create bucket ok')
        end
    }
}
--- request
GET /t

--- timeout: 15
--- response_body_like chomp
failed to create bucket: InvalidArgument.*


=== TEST 8: test invalid metadata

--- http_config eval: $::HttpConfig
--- config
location = /t {
    rewrite_by_lua_block {
        local s3_client = require('resty.aws_s3.client')
        local tableutil = require('acid.tableutil')
        local client, err, errmsg = s3_client.new($TEST_NGINX_ACCESS_KEY,
                                                  $TEST_NGINX_SECRET_KEY,
                                                  $TEST_NGINX_ENDPOINT)
        if err ~= nil then
            ngx.say(string.format('failed to new s3_client: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('new s3_client ok')
        end

        local bucket_name = 'test-bucket-' .. tostring(math.random(10000, 99999))
        local resp, err, errmsg = client:create_bucket(
                {Bucket=bucket_name})
        if err ~= nil then
            ngx.say(string.format('failed to create bucket: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('bucket created')
        end

        local resp, err, errmsg = client:put_object(
                {Bucket=bucket_name, Key='test-key', Body='foo', Metadata='foo'})
        if err ~= nil then
            ngx.say(string.format('failed to put object: %s, %s', err, errmsg))
        else
            ngx.say('put object ok')
        end

        local resp, err, errmsg = client:put_object(
                {Bucket=bucket_name, Key='test-key', Body='foo', Metadata={foo=44}})
        if err ~= nil then
            ngx.say(string.format('failed to put object: %s, %s', err, errmsg))
        else
            ngx.say('put object ok')
        end

        local resp, err, errmsg = client:put_object(
                {Bucket=bucket_name, Key='test-key', Body='foo', Metadata={[3]='foo'}})
        if err ~= nil then
            ngx.say(string.format('failed to put object: %s, %s', err, errmsg))
        else
            ngx.say('put object ok')
        end

        local resp, err, errmsg = client:delete_bucket(
                {Bucket=bucket_name})
        if err ~= nil then
            ngx.say(string.format('failed to delete bucket: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('bucket deleted')
        end

    }
}
--- request
GET /t

--- timeout: 15
--- response_body_like chomp
new s3_client ok
bucket created
failed to put object: InvalidArgument.*
failed to put object: InvalidArgument.*
failed to put object: InvalidArgument.*
bucket deleted
