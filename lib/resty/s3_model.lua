local s2xml = require('s2xml')
local tableutil = require('acid.tableutil')
local _M = {}

local meta_prefix = 'x-amz-meta-'
local date_format = '!%a, %d %b %Y %T GMT'

local empty_schema = {
    checker = {
    },
}

local string_schema = {
    checker = {
        ['type'] = 'string',
    },
}

local number_schema = {
    checker = {
        {
            ['type'] = 'integer',
        },
        {
            ['type'] = 'float',
        },
    },
}

_M.canned_acl = {
    ['private']=true,
    ['public-read']=true,
    ['public-read-write']=true,
    ['authenticated-read']=true,
}

_M.param_to_header_name = {
    ACL='x-amz-acl',
    ContentType='Content-Type',
    ContentMD5='Content-MD5',
    GrantRead='x-amz-grant-read',
    GrantReadACP='x-amz-grant-read-acp',
    GrantWrite='x-amz-grant-write',
    GrantWriteACP='x-amz-grant-write-acp',
    GrantFullControl='x-amz-grant-full-control',
    CopySource='x-amz-copy-source',
    CopySourceIfMatch='x-amz-copy-source-if-match',
    CopySourceIfNoneMatch='x-amz-copy-source-if-none-match',
    CopySourceIfModifiedSince='x-amz-copy-source-if-modified-since',
    CopySourceIfUnmodifiedSince='x-amz-copy-source-if-unmodified-since',
    MetadataDirective='x-amz-metadata-directive',
}

_M.param_to_arg_name = {
    Delimiter='delimiter',
    EncodingType='encodingtype',
    Marker='marker',
    MaxKeys='max-keys',
    Prefix='prefix',
    VersionId='versionId',
}


local function generate_service_uri()
    local uri = '/'
    return uri, nil, nil
end


local function generate_bucket_uri(params)
    local uri = '/' .. params.Bucket
    return uri, nil, nil
end


local function generate_object_uri(params)
    local uri = string.format('/%s/%s', params.Bucket, params.Key)
    return uri, nil, nil
end


local function generate_empty_query_args()
    return {}, nil, nil
end


local function generate_acl_query_args()
    return {acl=true}, nil, nil
end


local function generate_args_from_params(params)
    local query_args = {}

    for name, value in pairs(params) do
        local parameter_model = _M.parameters[name]
        if parameter_model.add_query_args ~= nil then
            local _, err, errmsg = parameter_model.add_query_args(
                    query_args, name, value)
            if err ~= nil then
                return nil, err, errmsg
            end
        end
    end

    return query_args, nil, nil
end


local function generate_empty_headers()
    return {}, nil, nil
end


local function generate_headers_from_params(params)
    local headers = {}

    for name, value in pairs(params) do
        local parameter_model = _M.parameters[name]
        if parameter_model.add_headers ~= nil then
            local _, err, errmsg = parameter_model.add_headers(
                    headers, name, value)
            if err ~= nil then
                return nil, err, errmsg
            end
        end
    end

    return headers, nil, nil
end


local function generate_empty_body()
    return '', nil, nil
end


local function generate_upload_body(params)
    local body = params.Body
    if type(body) == 'string' then
        return body, nil, nil
    end

    local file_handle, err = io.open(body.file_path, 'rb')
    if err ~= nil then
        return nil, 'OpenFileError', string.format(
                'failed to open file: %s, %s', body.file_path, err)
    end

    return {
        file_path=body.file_path,
        file_handle=file_handle,
    }, nil, nil
end


local function generate_put_acl_body(params)
    local acp = params.AccessControlPolicy
    if acp == nil then
        return '', nil, nil
    end

    local grants = acp.Grants

    local standared_acp = {
        __attr = {
            xmlns='http://s3.amazonaws.com/doc/2006-03-01/',
        },
    }
    standared_acp.Owner = acp.Owner
    standared_acp.AccessControlList = {
        Grant = {},
    }

    for _, grant in ipairs(grants) do
        local standared_grant = {}
        standared_grant.Permission = grant.Permission

        local grantee = grant.Grantee

        standared_grant.Grantee = {
            __attr = {
                ['xmlns:xsi']  = 'http://www.w3.org/2001/XMLSchema-instance',
            },
        }

        if grantee.Type == 'CanonicalUser' then
            standared_grant.Grantee.ID = grantee.ID
            standared_grant.Grantee.__attr['xsi:type'] = 'CanonicalUser'
        elseif grantee.Type == 'AmazonCustomerByEmail' then
            standared_grant.Grantee.EmailAddress = grantee.EmailAddress
            standared_grant.Grantee.__attr['xsi:type'] = 'AmazonCustomerByEmail'
        else
            standared_grant.Grantee.URI = grantee.URI
            standared_grant.Grantee.__attr['xsi:type'] = 'Group'
        end

        table.insert(standared_acp.AccessControlList.Grant, standared_grant)
    end

    local xml_acp, err, errmsg = s2xml.to_xml('AccessControlPolicy',
                                              standared_acp)
    if err ~= nil then
        return nil, 'XMLEncodeError', string.format(
                'failed to xml encode AccessControlPolicy: %s, %s',
                err, errmsg)
    end

    return xml_acp, nil, nil
end


local function common_add_param_arg(query_args, name, value)
    local arg_name = _M.param_to_arg_name[name]
    query_args[arg_name] = tostring(value)
    return true, nil, nil
end


local function common_add_param_header(headers, name, value)
    local header_name = _M.param_to_header_name[name]
    headers[header_name] = tostring(value)
    return true, nil, nil
end


local function add_metadata_headers(headers, name, value)
    for k, v in pairs(value) do
        local header_name = meta_prefix .. k
        headers[header_name] = v
    end
    return true, nil, nil
end


local function add_date_header(headers, name, value)
    local header_name = _M.param_to_header_name[name]
    headers[header_name] = os.date(date_format, value)
    return true, nil, nil
end


local function add_copy_source_header(headers, name, value)
    local header_name = _M.param_to_header_name[name]
    if type(value) == 'string' then
        headers[header_name] = value
    else
        headers[header_name] = string.format('%s/%s', value.Bucket, value.Key)
    end

    return true, nil, nil
end


local function common_parse_response(http_response)
    local response = {
        ResponseMetadata = {
            HTTPStatusCode = http_response.status,
            HTTPHeaders = {},
        },
    }

    for k, v in pairs(http_response.headers) do
        local lower_header_name = k:lower()
        response.ResponseMetadata.HTTPHeaders[lower_header_name] = v
    end

    local lower_headers = response.ResponseMetadata.HTTPHeaders
    response.ResponseMetadata.RequestId = lower_headers['x-amz-request-id']

    return response, nil, nil
end


local function parse_put_object_response(http_response)
    local response, err, errmsg = common_parse_response(http_response)
    if err ~= nil then
        return nil, err, errmsg
    end

    local lower_headers = response.ResponseMetadata.HTTPHeaders
    response['ETag'] = lower_headers.etag

    return response, nil, nil
end


local function parse_get_object_response(http_response)
    local response, err, errmsg = common_parse_response(http_response)
    if err ~= nil then
        return nil, err, errmsg
    end

    local lower_headers = response.ResponseMetadata.HTTPHeaders
    response.Body = http_response.body
    response.AcceptRanges = lower_headers['accept-ranges']
    response.ContentType = lower_headers['content-type']
    response.ContentLength = lower_headers['content-length']
    response.ETag = lower_headers.etag
    response.LastModified = lower_headers['last-modified']

    response.Metadata = {}
    for k, v in pairs(lower_headers) do
        if string.sub(k, 1, #meta_prefix) == meta_prefix then
            local meta_name = string.sub(k, #meta_prefix + 1)
            response.Metadata[meta_name] = v
        end
    end

    return response, nil, nil
end


local function parse_copy_object_response(http_response)
    local response, err, errmsg = common_parse_response(http_response)
    if err ~= nil then
        return nil, err, errmsg
    end

    local body, err, errmsg = http_response.body.read(1024 * 1024 * 10)
    if err ~= nil then
        return nil, 'ReadResponseBodyError', string.format(
                'failed to read response body: %s, %s', err, errmsg)
    end

    local result, err, errmsg = s2xml.from_xml(body)
    if err ~= nil then
        return nil, 'InvalidResponseXML', string.format(
                'the response XML is invalid: %s, %s', err, errmsg)
    end

    response.CopyObjectResult = {
        LastModified = result.CopyObjectResult.LastModified,
        ETag = result.CopyObjectResult.ETag,
    }

    return response, nil, nil
end


local function parse_download_file_response(http_response, params)
    local file_handle, err = io.open(params.Filename, 'wb')
    if err ~= nil then
        return nil, 'OpenFileError', string.format(
                'failed to open file: %s to write', params.Filename)
    end

    while true do
        local s, err, errmsg = http_response.body.read(1024 * 1024)
        if err ~= nil then
            return nil, 'ReadResponseBodyError', string.format(
                    'failed to read response body: %s, %s', err, errmsg)
        end
        if s == '' then
            break
        end
        file_handle:write(s)
    end

    file_handle:close()

    return true, nil, nil
end


local function get_tag_value(value)
    if type(value) == 'table' then
        return value[1] or ''
    end
    return value
end


local function parse_list_objects_response(http_response)
    local response, err, errmsg = common_parse_response(http_response)
    if err ~= nil then
        return nil, err, errmsg
    end

    local body, err, errmsg = http_response.body.read(1024 * 1024 * 10)
    if err ~= nil then
        return nil, 'ReadResponseBodyError', string.format(
                'failed to read response body: %s, %s', err, errmsg)
    end

    local result, err, errmsg = s2xml.from_xml(body)
    if err ~= nil then
        return nil, 'InvalidResponseXML', string.format(
                'the response XML is invalid: %s, %s', err, errmsg)
    end

    local list_result = result.ListBucketResult

    response.Delimiter = get_tag_value(list_result.Delimiter)
    response.MaxKeys = tonumber(get_tag_value(list_result.MaxKeys))
    response.Prefix = get_tag_value(list_result.Prefix)
    response.Marker = get_tag_value(list_result.Marker)
    response.EncodingType = get_tag_value(list_result.EncodingType)
    response.IsTruncated = get_tag_value(list_result.IsTruncated) == 'true'
    response.Name = get_tag_value(list_result.Name)

    if list_result.Contents == nil then
        return response, nil, nil
    end

    if #list_result.Contents == 0 then
        list_result.Contents = { list_result.Contents }
    end

    response.Contents = {}
    for _, object in ipairs(list_result.Contents) do
        object.Size = tonumber(object.Size)
        table.insert(response.Contents, object)
    end

    return response, nil, nil
end


local function parse_list_buckets_response(http_response)
    local response, err, errmsg = common_parse_response(http_response)
    if err ~= nil then
        return nil, err, errmsg
    end

    local body, err, errmsg = http_response.body.read(1024 * 1024 * 10)
    if err ~= nil then
        return nil, 'ReadResponseBodyError', string.format(
                'failed to read response body: %s, %s', err, errmsg)
    end

    local result, err, errmsg = s2xml.from_xml(body)
    if err ~= nil then
        return nil, 'InvalidResponseXML', string.format(
                'the response XML is invalid: %s, %s', err, errmsg)
    end

    response.Owner = result.ListAllMyBucketsResult.Owner
    response.Owner.DisplayName = get_tag_value(response.Owner.DisplayName)
    response.Buckets = result.ListAllMyBucketsResult.Buckets.Bucket

    if response.Buckets == nil then
        response.Buckets = {}
    end

    if response.Buckets.Name ~= nil then
        response.Buckets = {response.Buckets}
    end

    return response, nil, nil
end


local function parse_get_acl_response(http_response)
    local response, err, errmsg = common_parse_response(http_response)
    if err ~= nil then
        return nil, err, errmsg
    end

    local body, err, errmsg = http_response.body.read(1024 * 1024 * 10)
    if err ~= nil then
        return nil, 'ReadResponseBodyError', string.format(
                'failed to read response body: %s, %s', err, errmsg)
    end

    local result, err, errmsg = s2xml.from_xml(body)
    if err ~= nil then
        return nil, 'InvalidResponseXML', string.format(
                'the response XML is invalid: %s, %s', err, errmsg)
    end

    response.Owner = result.AccessControlPolicy.Owner
    response.Owner.DisplayName = get_tag_value(response.Owner.DisplayName)
    response.Grants = {}

    local grants = result.AccessControlPolicy.AccessControlList.Grant

    if #grants == 0 then
        grants = { grants }
    end

    for _, grant in ipairs(grants) do
        local standared_grant = {}
        standared_grant.Permission = grant.Permission
        grant.Grantee.Type = grant.Grantee.__attr['xsi:type']
        grant.Grantee.DisplayName = get_tag_value(grant.Grantee.DisplayName)
        grant.Grantee.__attr = nil
        standared_grant.Grantee = grant.Grantee
        table.insert(response.Grants, standared_grant)
    end

    return response, nil, nil
end


local grant_checker_schema = {
    ['type']='dict',
    sub_schema={
        Permission={
            required=true,
            checker={
                ['type']='string',
                enum={'FULL_CONTROL',
                      'WRITE',
                      'WRITE_ACP',
                      'READ',
                      'READ_ACP',},
            },
        },
        Grantee={
            required=true,
            checker={
                ['type']='dict',
                sub_schema={
                    Type={
                        required=true,
                        checker={
                            ['type']='string',
                            enum={'CanonicalUser',
                                  'AmazonCustomerByEmail',
                                  'Group',},
                        },
                    },
                    DisplayName={
                        checker={
                            ['type']='string',
                        },
                    },
                    ID={
                        checker={
                            ['type']='string',
                        },
                    },
                    EmailAddress={
                        checker={
                            ['type']='string',
                        },
                    },
                    URI={
                        checker={
                            ['type']='string',
                        },
                    },
                },
            },
        },
    },
}


_M.parameters = {
    Bucket={
        schema=string_schema,
        add_query_args=nil,
        add_headers=nil,
    },
    Key={
        schema=string_schema,
        add_query_args=nil,
        add_headers=nil,
    },
    Body={
        schema={
            checker={
                {
                    ['type']='string',
                },
                {
                    ['type']='dict',
                    sub_schema={
                        file_path={
                            required=true,
                            checker={
                                ['type']='string',
                            },
                        }
                    },
                }
            },
        },
        add_query_args=nil,
        add_headers=nil,
    },
    ACL={
        schema={
            checker={
                ['type']='string',
                enum={'private', 'public-read',
                      'public-read-write', 'authenticated-read'},
            },
        },
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    ContentType={
        schema=string_schema,
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    ContentMD5={
        schema=string_schema,
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    GrantRead={
        schema=string_schema,
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    GrantReadACP={
        schema=string_schema,
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    GrantWrite={
        schema=string_schema,
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    GrantWriteACP={
        schema=string_schema,
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    GrantFullControl={
        schema=string_schema,
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    Metadata={
        schema={
            checker={
                ['type']='dict',
                key_checker={
                    ['type']='string',
                },
                value_checker={
                    ['type']='string',
                },
            },
        },
        add_query_args=nil,
        add_headers=add_metadata_headers,
    },
    Delimiter={
        schema=string_schema,
        add_query_args=common_add_param_arg,
        add_headers=nil,
    },
    EncodingType={
        schema=string_schema,
        add_query_args=common_add_param_arg,
        add_headers=nil,
    },
    Marker={
        schema=string_schema,
        add_query_args=common_add_param_arg,
        add_headers=nil,
    },
    MaxKeys={
        schema=number_schema,
        add_query_args=common_add_param_arg,
        add_headers=nil,
    },
    Prefix={
        schema=string_schema,
        add_query_args=common_add_param_arg,
        add_headers=nil,
    },
    CopySource={
        schema={
            checker={
                {
                    ['type']='string',
                },
                {
                    ['type']='dict',
                    sub_schema={
                        Bucket={
                            required=true,
                            checker={
                                ['type']='string',
                            },
                        },
                        Key={
                            required=true,
                            checker={
                                ['type']='string',
                            },
                        },
                    },
                }
            },
        },
        add_query_args=nil,
        add_headers=add_copy_source_header,
    },
    CopySourceIfMatch={
        schema=string_schema,
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    CopySourceIfNoneMatch={
        schema=string_schema,
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    CopySourceIfModifiedSince={
        schema=number_schema,
        add_query_args=nil,
        add_headers=add_date_header,
    },
    CopySourceIfUnmodifiedSince={
        schema=number_schema,
        add_query_args=nil,
        add_headers=add_date_header,
    },
    MetadataDirective={
        schema=string_schema,
        add_query_args=nil,
        add_headers=common_add_param_header,
    },
    Filename={
        schema=string_schema,
        add_query_args=nil,
        add_headers=nil,
    },
    AccessControlPolicy={
        schema={
            checker={
                ['type']='dict',
                sub_schema={
                    Owner={
                        required=true,
                        checker={
                            ['type']='dict',
                            sub_schema={
                                ID={
                                    required=true,
                                    checker={
                                        ['type']='string',
                                    },
                                },
                                DisplayName={
                                    checker={
                                        ['type']='string',
                                    },
                                },
                            },
                        },
                    },
                    Grants={
                        required=true,
                        checker={
                            ['type']='array',
                            element_checker=grant_checker_schema
                        },
                    },
                },
            },
        },
        add_query_args=nil,
        add_headers=nil,
    },
    VersionId={
        schema=string_schema,
        add_query_args=common_add_param_arg,
        add_headers=nil,
    },
}


_M.methods = {}


_M.methods.get_object = {
    verb = 'GET',
    generate_uri = generate_object_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
        Key=tableutil.update({required=true},
                             _M.parameters.Key.schema),
    },
    generate_query_args = generate_empty_query_args,
    generate_headers = generate_empty_headers,
    generate_body = generate_empty_body,
    status_code = 200,
    parse_response = parse_get_object_response,
}


_M.methods.put_object = {
    verb = 'PUT',
    generate_uri = generate_object_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
        Key=tableutil.update({required=true},
                             _M.parameters.Key.schema),
        Body=tableutil.update({required=true},
                               _M.parameters.Body.schema),
        ACL=_M.parameters.ACL.schema,
        ContentType=_M.parameters.ContentType.schema,
        GrantRead=_M.parameters.GrantRead.schema,
        GrantReadACP=_M.parameters.GrantReadACP.schema,
        GrantWriteACP=_M.parameters.GrantWriteACP.schema,
        GrantFullControl=_M.parameters.GrantFullControl.schema,
        Metadata=_M.parameters.Metadata.schema,
    },
    generate_query_args = generate_empty_query_args,
    generate_headers = generate_headers_from_params,
    generate_body = generate_upload_body,
    status_code = 200,
    parse_response = parse_put_object_response,
}


_M.methods.delete_object = {
    verb = 'DELETE',
    generate_uri = generate_object_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
        Key=tableutil.update({required=true},
                             _M.parameters.Key.schema),
    },
    generate_query_args = generate_empty_query_args,
    generate_headers = generate_empty_headers,
    generate_body = generate_empty_body,
    status_code = 204,
    parse_response = common_parse_response,
}


_M.methods.copy_object = {
    verb = 'PUT',
    generate_uri = generate_object_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
        Key=tableutil.update({required=true},
                             _M.parameters.Key.schema),
        CopySource=tableutil.update({required=true},
                                    _M.parameters.CopySource.schema),
        CopySourceIfMatch=_M.parameters.CopySourceIfMatch.schema,
        CopySourceIfModifiedSince=
                _M.parameters.CopySourceIfModifiedSince.schema,
        CopySourceIfNoneMatch=_M.parameters.CopySourceIfNoneMatch.schema,
        CopySourceIfUnmodifiedSince=
                _M.parameters.CopySourceIfUnmodifiedSince.schema,
        ACL=_M.parameters.ACL.schema,
        ContentType=_M.parameters.ContentType.schema,
        GrantRead=_M.parameters.GrantRead.schema,
        GrantReadACP=_M.parameters.GrantReadACP.schema,
        GrantWriteACP=_M.parameters.GrantWriteACP.schema,
        GrantFullControl=_M.parameters.GrantFullControl.schema,
        Metadata=_M.parameters.Metadata.schema,
        MetadataDirective=_M.parameters.MetadataDirective.schema,
    },
    generate_query_args = generate_empty_query_args,
    generate_headers = generate_headers_from_params,
    generate_body = generate_empty_body,
    status_code = 200,
    parse_response = parse_copy_object_response,
}


_M.methods.create_bucket= {
    verb = 'PUT',
    generate_uri = generate_bucket_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
        ACL=_M.parameters.ACL.schema,
        GrantRead=_M.parameters.GrantRead.schema,
        GrantReadACP=_M.parameters.GrantReadACP.schema,
        GrantWrite=_M.parameters.GrantWrite.schema,
        GrantWriteACP=_M.parameters.GrantWriteACP.schema,
        GrantFullControl=_M.parameters.GrantFullControl.schema,
    },
    generate_query_args = generate_empty_query_args,
    generate_headers = generate_headers_from_params,
    generate_body = generate_empty_body,
    status_code = 200,
    parse_response = common_parse_response,
}


_M.methods.delete_bucket= {
    verb = 'DELETE',
    generate_uri = generate_bucket_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
    },
    generate_query_args = generate_empty_query_args,
    generate_headers = generate_empty_headers,
    generate_body = generate_empty_body,
    status_code = 204,
    parse_response = common_parse_response,
}


_M.methods.list_objects= {
    verb = 'GET',
    generate_uri = generate_bucket_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
        Delimiter=_M.parameters.Delimiter.schema,
        EncodingType=_M.parameters.EncodingType.schema,
        Marker=_M.parameters.Marker.schema,
        MaxKeys=_M.parameters.MaxKeys.schema,
        Prefix=_M.parameters.Prefix.schema,
    },
    generate_query_args = generate_args_from_params,
    generate_headers = generate_empty_headers,
    generate_body = generate_empty_body,
    status_code = 200,
    parse_response = parse_list_objects_response,
}


_M.methods.put_bucket_acl = {
    verb = 'PUT',
    generate_uri = generate_bucket_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
        ACL=_M.parameters.ACL.schema,
        GrantRead=_M.parameters.GrantRead.schema,
        GrantReadACP=_M.parameters.GrantReadACP.schema,
        GrantWrite=_M.parameters.GrantWrite.schema,
        GrantWriteACP=_M.parameters.GrantWriteACP.schema,
        GrantFullControl=_M.parameters.GrantFullControl.schema,
        AccessControlPolicy=_M.parameters.AccessControlPolicy.schema,
    },
    generate_query_args = generate_acl_query_args,
    generate_headers = generate_headers_from_params,
    generate_body = generate_put_acl_body,
    status_code = 200,
    parse_response = common_parse_response,
}


_M.methods.get_bucket_acl = {
    verb = 'GET',
    generate_uri = generate_bucket_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
    },
    generate_query_args = generate_acl_query_args,
    generate_headers = generate_empty_headers,
    generate_body = generate_empty_body,
    status_code = 200,
    parse_response = parse_get_acl_response,
}


_M.methods.put_object_acl = {
    verb = 'PUT',
    generate_uri = generate_object_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
        Key=tableutil.update({required=true},
                             _M.parameters.Key.schema),
        ACL=_M.parameters.ACL.schema,
        GrantRead=_M.parameters.GrantRead.schema,
        GrantReadACP=_M.parameters.GrantReadACP.schema,
        GrantWrite=_M.parameters.GrantWrite.schema,
        GrantWriteACP=_M.parameters.GrantWriteACP.schema,
        GrantFullControl=_M.parameters.GrantFullControl.schema,
        AccessControlPolicy=_M.parameters.AccessControlPolicy.schema,
        VersionId=_M.parameters.VersionId.schema,
    },
    generate_query_args = generate_acl_query_args,
    generate_headers = generate_headers_from_params,
    generate_body = generate_put_acl_body,
    status_code = 200,
    parse_response = common_parse_response,
}


_M.methods.get_object_acl = {
    verb = 'GET',
    generate_uri = generate_object_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
        Key=tableutil.update({required=true},
                             _M.parameters.Key.schema),
        VersionId=_M.parameters.VersionId.schema,
    },
    generate_query_args = generate_acl_query_args,
    generate_headers = generate_empty_headers,
    generate_body = generate_empty_body,
    status_code = 200,
    parse_response = parse_get_acl_response,
}


_M.methods.list_buckets= {
    verb = 'GET',
    generate_uri = generate_service_uri,
    params_schema = empty_schema,
    generate_query_args = generate_empty_query_args,
    generate_headers = generate_empty_headers,
    generate_body = generate_empty_body,
    status_code = 200,
    parse_response = parse_list_buckets_response,
}


_M.download_file_model = {
    verb = 'GET',
    generate_uri = generate_object_uri,
    params_schema = {
        Bucket=tableutil.update({required=true},
                                _M.parameters.Bucket.schema),
        Key=tableutil.update({required=true},
                             _M.parameters.Key.schema),
        Filename=_M.parameters.Filename.schema,
    },
    generate_query_args = generate_empty_query_args,
    generate_headers = generate_empty_headers,
    generate_body = generate_empty_body,
    status_code = 200,
    parse_response = parse_download_file_response,
}


return _M
