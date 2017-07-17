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

=== TEST 1: test copy object

--- http_config eval: $::HttpConfig
--- config
location = /t {
    rewrite_by_lua_block {
        local s3_client = require('resty.aws_s3.client')
        local tableutil = require('acid.tableutil')
        local client = s3_client.new(
                       $TEST_NGINX_ACCESS_KEY,
                       $TEST_NGINX_SECRET_KEY,
                       $TEST_NGINX_ENDPOINT)

        local bucket_name = 'test-bucket-' .. tostring(math.random(10000, 99999))
        local resp, err, errmsg = client:create_bucket(
                {Bucket=bucket_name})
        if err ~= nil then
            ngx.say(string.format('create bucket error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('bucket created')
        end


        local put_request = {
            Bucket=bucket_name,
            Key='test-key',
            ACL='public-read',
            Body='foo',
            ContentType='test_content_type',
            Metadata={
                foo1='bar1',
                foo2='bar2',
            },
        }

        local resp, err, errmsg = client:put_object(put_request)
        if err ~= nil then
            ngx.say(string.format('put object error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say(resp.ETag)
        end

        local copy_request = {
            Bucket=bucket_name,
            Key='copy-key',
            CopySource={Bucket=bucket_name, Key='test-key'},
            CopySourceIfNoneMatch='foo',
            CopySourceIfModifiedSince=os.time({year=2017, month=2, day=3, min=34, hour=23, sec=33}),
            MetadataDirective='COPY',
        }

        local resp, err, errmsg = client:copy_object(copy_request)
        if err ~= nil then
            ngx.say(string.format('copy object error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say(resp.CopyObjectResult.LastModified)
            ngx.say(resp.CopyObjectResult.ETag)
        end

        local get_request = {
            Bucket=bucket_name,
            Key='copy-key',
        }
        local resp, err, errmsg = client:get_object(get_request)
        if err ~= nil then
            ngx.say(string.format('get object error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say(resp.Metadata.foo1)
            ngx.say(resp.Metadata.foo2)
        end

        local delete_request = {
            Bucket=bucket_name,
            Key='test-key',
        }
        local resp, err, errmsg = client:delete_object(delete_request)
        if err ~= nil then
            ngx.say(string.format('delete object error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('deleted')
        end

        local delete_request = {
            Bucket=bucket_name,
            Key='copy-key',
        }
        local resp, err, errmsg = client:delete_object(delete_request)
        if err ~= nil then
            ngx.say(string.format('error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('deleted')
        end

        local resp, err, errmsg = client:delete_bucket(
                {Bucket=bucket_name})
        if err ~= nil then
            ngx.say(string.format('delete bucket error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('bucket deleted')
        end
    }
}
--- request
GET /t

--- timeout: 15
--- response_body_like
bucket created
"acbd18db4cc2f85cedef654fccc4a4d8"
[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{3}Z
"acbd18db4cc2f85cedef654fccc4a4d8"
bar1
bar2
deleted
deleted
bucket deleted
