return {
    no_consumer = true,
    fields = {
        token_introspect_url = { required = true, type = "string" },
        client_id = { required = true, type = "string" },
        client_secret = { required = true, type = "string" },
        auth_response_headers_to_forward = { type = "array", default = {} },
        auth_method = { required = false, type = "string", default = "client_secret_post" },
        timeout = { default = 10000, type = "number" },
        keepalive_timeout = { default = 60000, type = "number" },
    }
}