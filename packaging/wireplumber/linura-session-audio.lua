-- Linura bounded WirePlumber session-audio helper.
--
-- This script is invoked only through /usr/bin/wpexec by linurad. It deliberately
-- exposes two fixed operations: a canonical Audio/Sink snapshot and an
-- identity-bound volume update. It never executes arbitrary input as code.

local raw_args = ...
local args = raw_args

-- wpexec passes its optional SPA-JSON object as a WirePlumber Json value.
-- Convert that value through the sandboxed Json API; never evaluate argument
-- text as Lua code. A small recursion bound is sufficient for this flat typed
-- request and keeps malformed/unexpected inputs fail-closed.
if type(raw_args) ~= "table" then
  local parsed_ok, parsed_args = pcall(function()
    return raw_args:parse(2)
  end)
  if not parsed_ok or type(parsed_args) ~= "table" then
    error("linura-session-audio:invalid-arguments")
  end
  args = parsed_args
end

local MAX_SINKS = 256
local MAX_NODE_NAME_BYTES = 1024
local INVALID_ID = 4294967295

local function fail(code)
  error("linura-session-audio:" .. code)
end

local function canonical_decimal(value)
  return type(value) == "string"
      and value:match("^%d+$") ~= nil
      and (#value == 1 or value:sub(1, 1) ~= "0")
end

local function safe_node_name(value)
  return type(value) == "string"
      and #value > 0
      and #value <= MAX_NODE_NAME_BYTES
      and value:find("%c") == nil
end

local function integer_in_range(value, minimum, maximum)
  return type(value) == "number"
      and math.type(value) == "integer"
      and value >= minimum
      and value <= maximum
end

if type(args) ~= "table" or type(args.action) ~= "string" then
  fail("invalid-arguments")
end

local sinks = ObjectManager {
  Interest {
    type = "node",
    Constraint { "media.class", "equals", "Audio/Sink", type = "pw-global" },
  },
}

Core.require_api("default-nodes", "mixer", function(default_nodes, mixer)
  mixer["scale"] = "cubic"

  sinks:connect("installed", function(object_manager)
    local default_id = default_nodes:call("get-default-node", "Audio/Sink")

    if args.action == "observe" then
      local records = {}

      for node in object_manager:iterate() do
        if #records >= MAX_SINKS then
          fail("sink-limit")
        end

        local properties = node["global-properties"]
        local bound_id = node["bound-id"]
        local object_serial = properties["object.serial"]
        local node_name = properties["node.name"]
        local media_class = properties["media.class"]

        if not integer_in_range(bound_id, 0, INVALID_ID - 1)
            or not canonical_decimal(object_serial)
            or not safe_node_name(node_name)
            or media_class ~= "Audio/Sink" then
          fail("invalid-sink-identity")
        end

        local route = mixer:call("get-volume", bound_id)
        if type(route) ~= "table"
            or type(route.volume) ~= "number"
            or route.volume ~= route.volume
            or route.volume < 0.0
            or route.volume > 10.0
            or type(route.mute) ~= "boolean" then
          fail("invalid-volume-state")
        end

        local volume_percent = math.floor(route.volume * 100.0 + 0.5)
        if volume_percent < 0 or volume_percent > 1000 then
          fail("volume-out-of-range")
        end

        records[#records + 1] = {
          node_id = bound_id,
          object_serial = object_serial,
          node_name = node_name,
          is_default = default_id == bound_id,
          volume_percent = volume_percent,
          muted = route.mute,
        }
      end

      table.sort(records, function(left, right)
        return left.node_id < right.node_id
      end)

      print("protocol\t1")
      for _, record in ipairs(records) do
        print(string.format(
          "sink\t%d\t%s\t%s\t%d\t%d\t%d",
          record.node_id,
          record.object_serial,
          record.node_name,
          record.is_default and 1 or 0,
          record.volume_percent,
          record.muted and 1 or 0
        ))
      end
      Core.quit()
      return
    end

    if args.action == "set-volume" then
      if not integer_in_range(args.node_id, 0, INVALID_ID - 1)
          or not canonical_decimal(args.object_serial)
          or not safe_node_name(args.node_name)
          or not integer_in_range(args.volume_percent, 0, 100) then
        fail("invalid-set-volume-arguments")
      end

      local matched = nil
      local match_count = 0
      for node in object_manager:iterate() do
        local properties = node["global-properties"]
        local bound_id = node["bound-id"]
        if bound_id == args.node_id
            and properties["object.serial"] == args.object_serial
            and properties["node.name"] == args.node_name
            and properties["media.class"] == "Audio/Sink" then
          matched = node
          match_count = match_count + 1
        end
      end

      if match_count ~= 1 or matched == nil then
        fail("identity-mismatch")
      end

      -- Do not yield between identity resolution and the mixer action. The
      -- ObjectManager proxy and mixer cache therefore refer to the same
      -- WirePlumber event-loop view of the exact sink that was authorized.
      local matched_id = matched["bound-id"]
      if matched_id ~= args.node_id then
        fail("identity-changed")
      end

      local changed = mixer:call("set-volume", matched_id, args.volume_percent / 100.0)
      if changed ~= true then
        fail("set-volume-failed")
      end

      print("ok\t1")
      Core.quit()
      return
    end

    fail("unsupported-action")
  end)

  sinks:activate()
end)
