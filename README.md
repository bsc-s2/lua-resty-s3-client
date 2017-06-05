Name
====

lua-resty-s3-client - Lua AWS S3 client for ngx_lua

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Description](#description)
* [Synopsis](#synopsis)
* [Methods](#methods)
    * [new](#new)
    * [methods](#methods)
    * [download_file](#download_file)
    * [generate_presigned_url](#generate_presigned_url)
* [Installation](#installation)
* [Author](#author)
* [Copyright and License](#copyright-and-license)

Status
======

This library is considered production ready.

Description
===========

This Lua library is a AWS S3 client for the ngx_lua nginx module:

This Lua library takes advantage of ngx_lua's cosocket API, which ensures
100% nonblocking behavior.

Note that s2http, s2xml, awsauth is required

Synopsis
========

```lua

    server {
        location /test {
            content_by_lua_block {
                local s3_client = require "resty.s3_client"
                local client, err, msg = s3_client.new('access_key',
                                                       'secrest_key',
                                                       's3.amazonaws.com')
                if err ~= nil then
                    ngx.say('failed to new s3_client')
                    ngx.exit(ngx.HTTP_OK)
                end

                local resp, err, msg = client:create_bucket(
                        {Bucket='test-bucket'})
                if err ~= nil then
                    ngx.say('failed to create bucket')
                    ngx.exit(ngx.HTTP_OK)
                end

                local resp, err, msg = client:put_object(
                    {
                        Bucket='test-bucket',
                        Key='test-key',
                        ACL='public-read',
                        ContentType='image/jpg',
                        Metadata={
                            foo1='bar1',
                            foo2='bar2',
                        },
                        Body='file content as a string'  -- or use file name
                        -- Body={file_path='path/to/my/file'}
                    })
                if err ~= nil then
                    ngx.say('failed to put object')
                    ngx.exit(ngx.HTTP_OK)
                end

                local resp, err, msg = client:get_object(
                        {Bucket='test-bucket', Key='test-key'})
                if err ~= nil then
                    ngx.say('failed to get object')
                    ngx.exit(ngx.HTTP_OK)
                end

                local file_content, err, msg = resp.Body.read(1024 * 1024)
                if err ~= nil
                    ngx.say('failed to read body')
                    ngx.exit(ngx.HTTP_OK)
                end

                ngx.say('file content is: ' .. file_content)

                local presigned_url, err, msg = client:generate_presigned_url(
                        'get_object', {Bucket='test-bucket', Key='test-key'},
                        {ExpiresIn=3600})
                if err ~= nil then
                    ngx.say('failed to genearte presigned get object url')
                    ngx.exit(ngx.HTTP_OK)
                end

                ngx.say('presigned download url: ' .. presigned_url)
            }
        }
    }
```

[Back to TOC](#table-of-contents)

Methods
=======

[Back to TOC](#table-of-contents)

new
---
`syntax: client, err, msg = s3_client:new(access_key, secret_key, endpoint, client_opts)`

Creates a s3_client object. In case of failures, returns `nil` and a error code and a error message.

The `client_opts` argument is a Lua table holding the following keys:

* `timeout`

    the timeout for the request socket.


methods
---
`syntax: client, err, msg = client:<client_method>(params, opts)`

implemented client methods are: 'get_object',  'put_object', 'delete_object', 'copy_object',
 'create_bucket', 'delete_bucket', 'list_objects', 'put_bucket_acl', 'get_bucket_acl',
  'put_object_acl', 'get_object_acl', 'list_buckets'.


The `params` is a Lua table contain the parameters corresponding to that client method,
the parameters are all the same as [aws python sdk](https://boto3.readthedocs.io/en/latest/reference/services/s3.html#client).

The `opts` is a Lua table holding the following optional keys:

* `sign_payload`

    if sign the payload, the default is false.

* `extra_query_args`

    is a Lua table contain extra query args to add to query string.

* `extra_headers`

    is a Lua table contain extra headers to send.

The reaponse is almost the same as aws python sdk


download_file
---
`syntax: ok, err, msg = client:download_file(Bucket, Key, Filename, opts)`

Download an object to a file.

generate_presigned_url
---
`syntax: url, err, msg = client:generate_presigned_url(method, params, opts)`

Generate a presigned url.

Installation
============

copy the files to a correct location

[Back to TOC](#table-of-contents)


Author
======

Renzhi (任稚) <zhi.ren@baishancloud.com>.

[Back to TOC](#table-of-contents)

Copyright and License
=====================

The MIT License (MIT)

Copyright (c) 2016 Renzhi (任稚) <zhi.ren@baishancloud.com>

[Back to TOC](#table-of-contents)
