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

=== TEST 1: test list objects

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
            Body='1111',
        }
        local resp, err, errmsg = client:put_object(put_request)
        if err ~= nil then
            ngx.say(string.format('put object error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        end

        local list_request = {
            Bucket=bucket_name,
            Delimiter='/',
            EncodingType='url',
            Marker='test',
            MaxKeys=1,
            Prefix='test-key',
        }

        local resp, err, errmsg = client:list_objects(list_request)
        if err ~= nil then
            ngx.say(string.format('list objects error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('Delimiter is /: ' .. tostring(resp.Delimiter == '/'))
            ngx.say('Marker is test: ' .. tostring(resp.Marker == 'test'))
            ngx.say('MaxKeys is 1: ' .. tostring(resp.MaxKeys == 1))
            ngx.say('Prefix is test-key: ' .. tostring(resp.Prefix == 'test-key'))
            ngx.say('length of Contents is 1: ' .. tostring(#resp.Contents == 1))
            ngx.say('Key is test-key: ' .. tostring(resp.Contents[1].Key == 'test-key'))
        end

        local delete_request = {
            Bucket=bucket_name,
            Key='test-key',
        }
        local resp, err, errmsg = client:delete_object(delete_request)
        if err ~= nil then
            ngx.say(string.format('delete objects error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say('object deleted')
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
Delimiter is /: true
Marker is test: true
MaxKeys is 1: true
Prefix is test-key: true
length of Contents is 1: true
Key is test-key: true
object deleted
bucket deleted
