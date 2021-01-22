local BasePlugin = require "kong.plugins.base_plugin"
local access = require "kong.plugins.oauth2-token-introspection-request.access"

local OAut2TokenIntrospectionRequest = BasePlugin:extend()

OAut2TokenIntrospectionRequest.PRIORITY = 900

function OAut2TokenIntrospectionRequest:new()
  OAut2TokenIntrospectionRequest.super.new(self, "oauth2-token-introspection-request")
end

function OAut2TokenIntrospectionRequest:access(conf)
  OAut2TokenIntrospectionRequest.super.access(self)

  access.execute(conf)
end

return OAut2TokenIntrospectionRequest
