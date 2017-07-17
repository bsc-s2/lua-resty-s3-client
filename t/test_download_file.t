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

=== TEST 1: test download file

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


        local tmp_download_file_name = 'tmp_download_file.txt'
        local put_file_content = string.rep('0', 1024 * 1024 + 1)

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
            Body=put_file_content,
        }
        local resp, err, errmsg = client:put_object(put_request)
        if err ~= nil then
            ngx.say(string.format('put object error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say(resp.ETag)
        end

        local resp, err, errmsg = client:download_file(bucket_name,
                                                       'test-key',
                                                       tmp_download_file_name)
        if err ~= nil then
            ngx.say(string.format('download file error: %s, %s', err, errmsg))
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.say(resp)
        end

        local file_handle, err = io.open(tmp_download_file_name, 'rb')
        if err ~= nil then
            ngx.say(string.format('open file error: %s', err))
            ngx.exit(ngx.HTTP_OK)
        end

        local file_content = file_handle:read(1024 * 1024 * 2)
        file_handle:close()

        ngx.say(string.format('file content is correct: %s',
                 tostring(file_content == put_file_content)))

        os.remove(tmp_download_file_name)

        local resp, err, errmsg = client:delete_object(
                {Bucket=bucket_name, Key='test-key'})
        if err ~= nil then
            ngx.say(string.format('delete object error: %s, %s', err, errmsg))
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

--- timeout: 1500
--- response_body_like
bucket created
"9afb2132ac78da6232e991e611f68765"
true
file content is correct: true
object deleted
bucket deleted
