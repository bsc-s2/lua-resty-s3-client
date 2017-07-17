local arg_checker = require('arg_schema_checker')
local aws_singer = require('resty.awsauth.aws_signer')
local resty_sha256 = require('resty.sha256')
local resty_string = require('resty.string')
local httpclient = require('acid.httpclient')
local s3_model = require('resty.s3_model')
local xml = require('s2xml')

local _M = {}

local mt = { __index = _M }


function _M.new(access_key, secret_key, endpoint, client_opts)
    if type(endpoint) ~= 'string' then
        return nil, 'InvalidArgument', string.format(
                'invalid endpoint: %s is not a string', tostring(endpoint))
    end

    local signer, err, errmsg = aws_singer.new(access_key, secret_key)
    if err ~= nil then
        return nil, err, errmsg
    end

    client_opts = client_opts or {}
    if type(client_opts) ~= 'table' then
        return nil, 'InvalidArgument', string.format(
                'invalid client_opts: %s, is not a table, is type: %s',
                tostring(client_opts), type(client_opts))
    end

    local client = {
        signer = signer,
        endpoint = endpoint,
        timeout = client_opts.timeout or 1000 * 60,
    }

    setmetatable(client, mt)

    for method, method_model in pairs(s3_model.methods) do
        client[method] = function(self, params, opts)
            return self:do_client_method(params, method_model, opts)
        end
    end

    return client, nil, nil
end


function _M.do_request(self, verb, uri, headers, body)
    local h = httpclient:new(self.endpoint, 80, self.timeout)
    h:send_request(uri, {
        method=verb,
        headers=headers,
    })

    if type(body) == 'table' then
        local file_path = body.file_path
        local file_handle = body.file_handle

        local _, err = file_handle:seek('set')
        if err ~= nil then
            return nil, 'SeekFileError', string.format(
                    'failed to seek set file: %s, %s', file_path, err)
        end

        local s = ''
        while s ~= nil do
            s = file_handle:read(1024 * 1024)
            if s ~= nil then
                h:send_body(s)
            end
        end
    else
        h:send_body(body)
    end

    h:finish_request()

    local read_body = function(size)
        return h:read_body(size)
    end

    local resp = {
        status = h.status,
        headers = h.headers,
        body = {
            read=read_body,
        },
    }
    return resp, nil, nil
end


local function get_stream_info(body, sign_payload)
    local file_path = body.file_path
    local file_handle = body.file_handle

    local file_size, err = file_handle:seek('end')
    if err ~= nil then
        return nil, 'SeekFileError', string.format(
                'failed to seek end file: %s, %s', file_path, err)
    end

    body.size = file_size

    if sign_payload ~= true then
        return true, nil, nil
    end

    local _, err = file_handle:seek('set')
    if err ~= nil then
        return nil, 'SeekFileError', string.format(
                'failed to seek set file: %s, %s', file_path, err)
    end

    local sha256 = resty_sha256:new()
    local total_size = 0
    local s = ''
    while s ~= nil do
        s = file_handle:read(1024 * 1024)
        if s ~= nil then
            sha256:update(s)
            total_size = total_size + #s
        end
    end

    local content_sha256 = sha256:final()
    content_sha256 = resty_string.to_hex(content_sha256)

    if total_size ~= file_size then
        return nil, 'FileSizeError', string.format(
                'the file size is: %d, but read %d bytes',
                file_size, total_size)
    end

    body.content_sha256 = content_sha256

    return true, nil, nil
end


local function parse_error(body)
    local short_body = body
    if #short_body > 512 then
        short_body = string.sub(short_body, 1, 512) .. '...'
    end
    local error_resp, err, errmsg = xml.from_xml(body)
    if err ~= nil then
        return nil, 'InvalidResponseError', string.format(
                'response: %s is not a valid xml, %s, %s',
                short_body, err, errmsg)
    end

    if type(error_resp) ~= 'table' then
        return nil, 'InvalidResponseError', string.format(
                'response: %s, is invalid', short_body)
    end

    if type(error_resp.Error) ~= 'table' then
        return nil, 'InvalidResponseError', string.format(
                'response: %s, does not contain Error', short_body)
    end

    local error_code = error_resp.Error.Code
    if error_code == nil then
        return nil, 'InvalidResponseError', string.format(
                'response: %s, does not contain Error Code', short_body)
    end

    local error_message = error_resp.Error.Message
    if error_message == nil then
        return nil, 'InvalidResponseError', string.format(
                'response: %s, does not contain Error Message', short_body)
    end

    return {
        code=tostring(error_code),
        message=tostring(error_message)
    }, nil, nil

end


function _M.get_signed_request(self, params, method_model, opts)
    local uri, err, errmsg = method_model.generate_uri(params)
    if err ~= nil then
        return nil, err, errmsg
    end
    local args, err, errmsg = method_model.generate_query_args(params)
    if err ~= nil then
        return nil, err, errmsg
    end
    local headers, err, errmsg = method_model.generate_headers(params)
    if err ~= nil then
        return nil, err, errmsg
    end

    local request = {
        verb = method_model.verb,
        uri = uri,
        args = args,
        headers = headers,
    }
    request.headers['Host'] = self.endpoint

    if type(opts.extra_query_args) == 'table' then
        for k, v in pairs(opts.extra_query_args) do
            request.args[tostring(k)] = tostring(v)
        end
    end

    if type(opts.extra_headers) == 'table' then
        for k, v in pairs(opts.extra_headers) do
            request.headers[tostring(k)] = tostring(v)
        end
    end

    local sign_payload = opts.sign_payload == true

    local body, err, errmsg = method_model.generate_body(params)
    if err ~= nil then
        return nil, err, errmsg
    end

    if type(body) == 'table' then
        local _, err, errmsg = get_stream_info(body, sign_payload)
        if err ~= nil then
            return nil, err, errmsg
        end

        request.headers['Content-Length'] = body.size

        if sign_payload == true then
            request.headers['X-Amz-Content-SHA256'] = body.content_sha256
        end
    else
        request.body = body
        request.headers['Content-Length'] = #body
    end

    local auth_ctx, err, errmsg = self.signer:add_auth_v4(
            request, {sign_payload=sign_payload})
    if err ~= nil then
        return nil, err, errmsg
    end

    request.body = body
    request.auth_ctx = auth_ctx

    return request, nil, nil
end


local function parse_http_response(resp, params, method_model, auth_ctx)
    if resp.status ~= method_model.status_code then
        local resp_body, err, errmsg = resp.body.read(1024 * 1024)
        if err ~= nil then
            return nil, 'ReadResponseBodyError', string.format(
                    'failed to read response body, %s, %s', err, errmsg)
        end
        local error_info, err, errmsg = parse_error(resp_body)
        if err ~= nil then
            return nil, 'ParseErrorResponseError', string.format(
                    'parse error response error: %s, %s',
                    err, errmsg)
        end

        local extra_message = ''
        if resp.status == 403 then
            extra_message = string.format(
                    ' client canonical request: %s, hex: %s',
                    auth_ctx.canonical_request,
                    resty_string.to_hex(auth_ctx.canonical_request))
        end
        return nil, error_info.code, error_info.message .. extra_message
    end

    local response, err, errmsg = method_model.parse_response(resp, params)
    if err ~= nil then
        return nil, err, errmsg
    end

    return response, nil, nil
end


function _M.do_client_method(self, params, method_model, opts)
    opts = opts or {}
    if type(opts) ~= 'table' then
        return nil, 'InvalidArgument', string.format(
                'invalid opts: %s, is not a table, is type: %s',
                tostring(opts), type(opts))
    end

    params = params or {}
    if type(params) ~= 'table' then
        return nil, 'InvalidArgument', string.format(
                'invalid params: %s, is not a table, is type: %s',
                tostring(params), type(params))
    end

    local _, err, errmsg = arg_checker.check_arguments(
            params, method_model.params_schema)
    if err ~= nil then
        return nil, 'InvalidArgument', string.format(
                'invalid params: %s, %s', err, errmsg)
    end

    local request, err, errmsg = self:get_signed_request(
            params, method_model, opts)
    if err ~= nil then
        return nil, err, errmsg
    end

    local resp, err, errmsg = self:do_request(request.verb,
                                              request.uri,
                                              request.headers,
                                              request.body)
    if err ~= nil then
        return nil, err, errmsg
    end

    local response, err, errmsg = parse_http_response(
            resp, params, method_model, request.auth_ctx)
    if err ~= nil then
        return nil, err, errmsg
    end

    return response, nil, nil
end


function _M.download_file(self, Bucket, Key, Filename, opts)
    local params = {
        Bucket=Bucket,
        Key=Key,
        Filename=Filename,
    }
    local resp, err, errmsg = self:do_client_method(
            params, s3_model.download_file_model, opts)
    if err ~= nil then
        return nil, err, errmsg
    end

    return resp, nil, nil
end


function _M.generate_presigned_url(self, method, params, opts)
    local method_model = s3_model.methods[method]
    if method_model == nil then
        return nil, 'InvalidArgument', string.format(
                'invalid method: %s', method)
    end

    params = params or {}
    if type(params) ~= 'table' then
        return nil, 'InvalidArgument', string.format(
                'invalid params: %s, is not a table, is type: %s',
                tostring(params), type(params))
    end

    local _, err, errmsg = arg_checker.check_arguments(
            params, method_model.params_schema)
    if err ~= nil then
        return nil, 'InvalidArgument', string.format(
                'invalid params: %s, %s', err, errmsg)
    end

    local request = {
        verb = method_model.verb,
        uri = method_model.generate_uri(params),
        args = method_model.generate_query_args(params),
        headers = method_model.generate_headers(params),
    }
    request.headers['Host'] = self.endpoint

    if type(opts.extra_query_args) == 'table' then
        for k, v in pairs(opts.extra_query_args) do
            request.args[tostring(k)] = tostring(v)
        end
    end

    if type(opts.extra_headers) == 'table' then
        for k, v in pairs(opts.extra_headers) do
            request.headers[tostring(k)] = tostring(v)
        end
    end

    local _, err, errmsg = self.signer:add_auth_v4(request,
                                                   {sign_payload=false,
                                                    query_auth=true,
                                                    expires=opts.ExpiresIn})
    if err ~= nil then
        return nil, err, errmsg
    end

    local scheme  = 'http'
    if opts.https == true then
        scheme = scheme .. 's'
    end
    local url = string.format('%s://%s%s', scheme, self.endpoint, request.uri)

    return url, nil, nil
end


return _M
