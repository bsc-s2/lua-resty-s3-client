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

=== TEST 1: test presigned get object url

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
            ngx.say(string.format('crated bucket error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('bucket created')
        end

        local put_request = {
            Bucket=bucket_name,
            Key='test-key',
            Body='foo',
        }

        local resp, err, errmsg = client:put_object(put_request)
        if err ~= nil then
            ngx.say(string.format('error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say(resp.ETag)
        end

        local get_request = {
            Bucket=bucket_name,
            Key='test-key',
        }

        local url, err ,errmsg = client:generate_presigned_url('get_object',
                                                               get_request,
                                                               {ExpiresIn=3600})
        if err ~= nil then
            ngx.say(string.format('failed to generate presigned url: %s, %s',
                                  err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('signed url: ' .. url)
        end

        local delete_request = get_request
        local resp, err, errmsg = client:delete_object(delete_request)
        if err ~= nil then
            ngx.say(string.format('delete object error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('object deleted')
        end

        local resp, err, errmsg = client:delete_bucket(
                {Bucket=bucket_name})
        if err ~= nil then
            ngx.say(string.format('deleted bucket error: %s, %s', err, errmsg))
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
bucket created
"acbd18db4cc2f85cedef654fccc4a4d8"
signed url: .*X-Amz-Signature=\w{64}
object deleted
bucket deleted
