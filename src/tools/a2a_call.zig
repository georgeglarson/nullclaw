const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const http_util = @import("../http_util.zig");
const RemoteAgentConfig = @import("../config_types.zig").RemoteAgentConfig;

const log = std.log.scoped(.a2a_call);

/// Test override for the HTTP send function, allowing unit tests to intercept
/// network calls without making real requests (same pattern as delegate.zig).
const TestSendFn = *const fn (
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    max_time: ?[]const u8,
) anyerror!http_util.HttpResponse;

var test_send_override: ?TestSendFn = null;

/// Returns true if the URL targets a private/internal network address where
/// plaintext HTTP is acceptable (RFC 1918 ranges, loopback, Tailscale CGNAT).
fn isPrivateUrl(url: []const u8) bool {
    // Strip scheme prefix to get the host portion.
    const after_scheme = if (std.mem.startsWith(u8, url, "http://"))
        url[7..]
    else if (std.mem.startsWith(u8, url, "https://"))
        url[8..]
    else
        url;

    // Extract hostname (before any ':' port or '/' path).
    var host_end: usize = 0;
    while (host_end < after_scheme.len) : (host_end += 1) {
        if (after_scheme[host_end] == ':' or after_scheme[host_end] == '/') break;
    }
    const host = after_scheme[0..host_end];

    // Check well-known private prefixes.
    if (std.mem.eql(u8, host, "localhost")) return true;
    if (std.mem.startsWith(u8, host, "127.")) return true;
    if (std.mem.startsWith(u8, host, "10.")) return true;
    if (std.mem.startsWith(u8, host, "192.168.")) return true;

    // 172.16.0.0/12
    if (std.mem.startsWith(u8, host, "172.")) {
        const dot2 = std.mem.indexOfPos(u8, host, 4, ".") orelse return false;
        const second_octet = std.fmt.parseInt(u8, host[4..dot2], 10) catch return false;
        if (second_octet >= 16 and second_octet <= 31) return true;
    }

    // Tailscale CGNAT range: 100.64.0.0/10 (100.64.x.x – 100.127.x.x)
    if (std.mem.startsWith(u8, host, "100.")) {
        const dot2 = std.mem.indexOfPos(u8, host, 4, ".") orelse return false;
        const second_octet = std.fmt.parseInt(u8, host[4..dot2], 10) catch return false;
        if (second_octet >= 64 and second_octet <= 127) return true;
    }

    return false;
}

/// A2A client tool — sends a task to a remote agent via Google's A2A protocol
/// (JSON-RPC 2.0 over HTTPS). Use when a task should be handled by a different
/// agent running on a separate system.
pub const A2aCallTool = struct {
    remote_agents: []const RemoteAgentConfig = &.{},

    pub const tool_name = "a2a_call";
    pub const tool_description = "Send a task to a remote agent via the A2A (Agent-to-Agent) protocol. Use when another agent on a different system should handle a subtask.";
    pub const tool_params =
        \\{"type":"object","properties":{"agent":{"type":"string","minLength":1,"description":"Name of the remote agent (must match a configured remote_agents entry)"},"message":{"type":"string","minLength":1,"description":"The message/task to send to the remote agent"},"context_id":{"type":"string","description":"Optional context ID for multi-turn conversations"}},"required":["agent","message"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *A2aCallTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *A2aCallTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const agent_name = root.getString(args, "agent") orelse
            return ToolResult.fail("Missing 'agent' parameter");

        const trimmed_agent = std.mem.trim(u8, agent_name, " \t\n");
        if (trimmed_agent.len == 0) {
            return ToolResult.fail("'agent' parameter must not be empty");
        }

        const message = root.getString(args, "message") orelse
            return ToolResult.fail("Missing 'message' parameter");

        const trimmed_message = std.mem.trim(u8, message, " \t\n");
        if (trimmed_message.len == 0) {
            return ToolResult.fail("'message' parameter must not be empty");
        }

        const context_id: ?[]const u8 = root.getString(args, "context_id");

        // Look up remote agent config.
        const remote = self.findRemoteAgent(trimmed_agent) orelse {
            const msg = std.fmt.allocPrint(allocator, "Unknown remote agent: '{s}'. Configure it in a2a.remote_agents.", .{trimmed_agent}) catch
                return ToolResult.fail("Unknown remote agent");
            return .{ .success = false, .output = "", .error_msg = msg };
        };

        // Reject URLs with userinfo (http://user:pass@host) — potential SSRF vector.
        const scheme_end = std.mem.indexOf(u8, remote.url, "://") orelse 0;
        const after_scheme = remote.url[@min(scheme_end + 3, remote.url.len)..];
        const host_part_end = std.mem.indexOf(u8, after_scheme, "/") orelse after_scheme.len;
        if (std.mem.indexOf(u8, after_scheme[0..host_part_end], "@") != null) {
            return ToolResult.fail("URLs with userinfo (@) are not allowed — potential SSRF vector");
        }

        // Validate URL scheme: HTTPS required unless targeting a private network.
        if (std.mem.startsWith(u8, remote.url, "http://") and !isPrivateUrl(remote.url)) {
            return ToolResult.fail("HTTPS required for remote agents on public networks. Use https:// or configure a private/Tailscale address.");
        }

        // Build and send the A2A request.
        return self.sendA2aRequest(allocator, remote, trimmed_message, context_id);
    }

    fn findRemoteAgent(self: *A2aCallTool, name: []const u8) ?RemoteAgentConfig {
        for (self.remote_agents) |agent| {
            if (std.mem.eql(u8, agent.name, name)) return agent;
        }
        return null;
    }

    fn sendA2aRequest(
        self: *A2aCallTool,
        allocator: std.mem.Allocator,
        remote: RemoteAgentConfig,
        message: []const u8,
        context_id: ?[]const u8,
    ) !ToolResult {
        _ = self;

        // Build the A2A endpoint URL.
        const url = try std.fmt.allocPrint(allocator, "{s}/a2a", .{remote.url});
        defer allocator.free(url);

        // Generate a simple message ID from timestamp.
        const msg_id = try std.fmt.allocPrint(allocator, "msg-{d}", .{std.time.milliTimestamp()});
        defer allocator.free(msg_id);

        // Escape message and context_id for JSON embedding.
        const escaped_message = try jsonEscape(allocator, message);
        defer allocator.free(escaped_message);

        // Build JSON-RPC request body.
        const body = if (context_id) |ctx| blk: {
            const escaped_ctx = try jsonEscape(allocator, ctx);
            defer allocator.free(escaped_ctx);
            break :blk try std.fmt.allocPrint(allocator,
                \\{{"jsonrpc":"2.0","id":"1","method":"message/send","params":{{"message":{{"role":"user","parts":[{{"kind":"text","text":"{s}"}}],"messageId":"{s}"}},"contextId":"{s}"}}}}
            , .{ escaped_message, msg_id, escaped_ctx });
        } else try std.fmt.allocPrint(allocator,
            \\{{"jsonrpc":"2.0","id":"1","method":"message/send","params":{{"message":{{"role":"user","parts":[{{"kind":"text","text":"{s}"}}],"messageId":"{s}"}}}}}}
        , .{ escaped_message, msg_id });
        defer allocator.free(body);

        // Build headers.
        var header_buf: [2][]const u8 = undefined;
        var header_count: usize = 0;

        const auth_header = if (remote.bearer_token) |token|
            try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{token})
        else
            null;
        defer if (auth_header) |h| allocator.free(h);

        if (auth_header) |h| {
            header_buf[header_count] = h;
            header_count += 1;
        }

        const headers = header_buf[0..header_count];

        // Build timeout string.
        const timeout_str = try std.fmt.allocPrint(allocator, "{d}", .{remote.timeout_secs});
        defer allocator.free(timeout_str);

        // Send request (or use test override).
        const response = if (test_send_override) |override|
            try override(allocator, url, body, headers, timeout_str)
        else
            http_util.curlPostWithStatusAndTimeout(allocator, url, body, headers, timeout_str) catch |err| {
                if (!builtin.is_test) {
                    log.err("a2a request to {s} failed: {s}", .{ remote.name, @errorName(err) });
                }
                return ToolResult.fail("A2A request failed: could not reach remote agent");
            };
        defer allocator.free(response.body);

        // Check HTTP status.
        if (response.status_code < 200 or response.status_code >= 300) {
            const err_msg = try std.fmt.allocPrint(allocator, "A2A request failed: HTTP {d}", .{response.status_code});
            return .{ .success = false, .output = "", .error_msg = err_msg };
        }

        // Parse response and extract agent text.
        return parseA2aResponse(allocator, response.body);
    }
};

/// Parse an A2A JSON-RPC response and extract the agent's reply text.
fn parseA2aResponse(allocator: std.mem.Allocator, body: []const u8) !ToolResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch {
        return ToolResult.fail("A2A response: invalid JSON");
    };
    defer parsed.deinit();

    const root_obj = if (parsed.value == .object) parsed.value.object else
        return ToolResult.fail("A2A response: expected JSON object");

    // Check for JSON-RPC error.
    if (root_obj.get("error")) |err_val| {
        if (err_val == .object) {
            if (err_val.object.get("message")) |msg| {
                if (msg == .string) {
                    const err_msg = try std.fmt.allocPrint(allocator, "A2A error: {s}", .{msg.string});
                    return .{ .success = false, .output = "", .error_msg = err_msg };
                }
            }
        }
        return ToolResult.fail("A2A error: unknown JSON-RPC error");
    }

    // Extract result.
    const result = if (root_obj.get("result")) |v| (if (v == .object) v.object else null) else null;
    if (result == null) return ToolResult.fail("A2A response: missing 'result' field");

    // Extract task state.
    const status = if (result.?.get("status")) |v| (if (v == .object) v.object else null) else null;
    const state_str = if (status) |s| (if (s.get("state")) |v| (if (v == .string) v.string else null) else null) else null;

    // Extract agent text from artifacts.
    const agent_text = extractArtifactText(result.?) orelse
        extractStatusMessageText(status);

    if (state_str) |state| {
        if (std.mem.eql(u8, state, "completed")) {
            const output = if (agent_text) |text|
                try allocator.dupe(u8, text)
            else
                try allocator.dupe(u8, "(completed with no response text)");
            return .{ .success = true, .output = output };
        }
        if (std.mem.eql(u8, state, "failed") or std.mem.eql(u8, state, "rejected")) {
            const detail = agent_text orelse "no details";
            const err_msg = try std.fmt.allocPrint(allocator, "A2A task {s}: {s}", .{ state, detail });
            return .{ .success = false, .output = "", .error_msg = err_msg };
        }
        // working, submitted, input-required, etc.
        const output = if (agent_text) |text|
            try std.fmt.allocPrint(allocator, "Task state: {s}\n{s}", .{ state, text })
        else
            try std.fmt.allocPrint(allocator, "Task state: {s} (awaiting completion)", .{state});
        return .{ .success = true, .output = output };
    }

    // No state found — return whatever text we got.
    if (agent_text) |text| {
        const output = try allocator.dupe(u8, text);
        return .{ .success = true, .output = output };
    }

    return ToolResult.fail("A2A response: could not extract result");
}

/// Extract text from result.artifacts[0].parts[0].text
fn extractArtifactText(result: std.json.ObjectMap) ?[]const u8 {
    const artifacts = result.get("artifacts") orelse return null;
    if (artifacts != .array) return null;
    if (artifacts.array.items.len == 0) return null;

    const first = artifacts.array.items[0];
    if (first != .object) return null;

    const parts = first.object.get("parts") orelse return null;
    if (parts != .array) return null;
    if (parts.array.items.len == 0) return null;

    const part = parts.array.items[0];
    if (part != .object) return null;

    const text = part.object.get("text") orelse return null;
    if (text != .string) return null;
    return text.string;
}

/// Extract text from result.status.message.parts[0].text (fallback).
fn extractStatusMessageText(status: ?std.json.ObjectMap) ?[]const u8 {
    const s = status orelse return null;
    const msg = s.get("message") orelse return null;
    if (msg != .object) return null;

    const parts = msg.object.get("parts") orelse return null;
    if (parts != .array) return null;
    if (parts.array.items.len == 0) return null;

    const part = parts.array.items[0];
    if (part != .object) return null;

    const text = part.object.get("text") orelse return null;
    if (text != .string) return null;
    return text.string;
}

/// Escape a string for safe embedding inside a JSON string value.
fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    try out.ensureTotalCapacity(allocator, input.len);
    for (input) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    var buf: [6]u8 = undefined;
                    const hex = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch continue;
                    try out.appendSlice(allocator, hex);
                } else {
                    try out.append(allocator, c);
                }
            },
        }
    }
    return try out.toOwnedSlice(allocator);
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "a2a_call tool name" {
    var t = A2aCallTool{};
    try std.testing.expectEqualStrings("a2a_call", t.tool().name());
}

test "a2a_call missing agent rejected" {
    const allocator = std.testing.allocator;
    var t = A2aCallTool{};
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "a2a_call missing message rejected" {
    const allocator = std.testing.allocator;
    var t = A2aCallTool{};
    const parsed = try root.parseTestArgs(
        \\{"agent":"ironclaw"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "a2a_call blank agent rejected" {
    const allocator = std.testing.allocator;
    var t = A2aCallTool{};
    const parsed = try root.parseTestArgs(
        \\{"agent":"  ","message":"hello"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "a2a_call blank message rejected" {
    const allocator = std.testing.allocator;
    var t = A2aCallTool{};
    const parsed = try root.parseTestArgs(
        \\{"agent":"ironclaw","message":"  "}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "a2a_call unknown agent rejected" {
    const allocator = std.testing.allocator;
    var agents = [_]RemoteAgentConfig{
        .{ .name = "ironclaw", .url = "https://example.com" },
    };
    var t = A2aCallTool{ .remote_agents = &agents };
    const parsed = try root.parseTestArgs(
        \\{"agent":"unknown","message":"hello"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.error_msg) |msg| allocator.free(msg);
    try std.testing.expect(!result.success);
}

test "a2a_call HTTPS required for public URLs" {
    const allocator = std.testing.allocator;
    var agents = [_]RemoteAgentConfig{
        .{ .name = "public-agent", .url = "http://example.com" },
    };
    var t = A2aCallTool{ .remote_agents = &agents };
    const parsed = try root.parseTestArgs(
        \\{"agent":"public-agent","message":"hello"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "a2a_call HTTP allowed for private IPs" {
    const allocator = std.testing.allocator;
    var agents = [_]RemoteAgentConfig{
        .{ .name = "local", .url = "http://192.168.1.100:3000" },
    };
    var t = A2aCallTool{ .remote_agents = &agents };

    // Override the send function to avoid real HTTP calls.
    test_send_override = testSendCompleted;
    defer {
        test_send_override = null;
    }

    const parsed = try root.parseTestArgs(
        \\{"agent":"local","message":"hello"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer allocator.free(result.output);
    try std.testing.expect(result.success);
}

test "a2a_call HTTP allowed for Tailscale CGNAT" {
    const allocator = std.testing.allocator;
    var agents = [_]RemoteAgentConfig{
        .{ .name = "ts-agent", .url = "http://100.123.240.34:3000" },
    };
    var t = A2aCallTool{ .remote_agents = &agents };

    test_send_override = testSendCompleted;
    defer {
        test_send_override = null;
    }

    const parsed = try root.parseTestArgs(
        \\{"agent":"ts-agent","message":"hello"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer allocator.free(result.output);
    try std.testing.expect(result.success);
}

test "a2a_call parses completed task response" {
    const allocator = std.testing.allocator;
    const body =
        \\{"jsonrpc":"2.0","id":"1","result":{"id":"task-1","status":{"state":"completed"},"artifacts":[{"parts":[{"kind":"text","text":"Here is the answer"}]}]}}
    ;
    const result = try parseA2aResponse(allocator, body);
    defer allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("Here is the answer", result.output);
}

test "a2a_call parses failed task response" {
    const allocator = std.testing.allocator;
    const body =
        \\{"jsonrpc":"2.0","id":"1","result":{"id":"task-1","status":{"state":"failed","message":{"parts":[{"kind":"text","text":"something broke"}]}}}}
    ;
    const result = try parseA2aResponse(allocator, body);
    defer if (result.error_msg) |msg| allocator.free(msg);
    try std.testing.expect(!result.success);
}

test "a2a_call parses JSON-RPC error response" {
    const allocator = std.testing.allocator;
    const body =
        \\{"jsonrpc":"2.0","id":"1","error":{"code":-32600,"message":"Invalid request"}}
    ;
    const result = try parseA2aResponse(allocator, body);
    defer if (result.error_msg) |msg| allocator.free(msg);
    try std.testing.expect(!result.success);
}

test "a2a_call jsonEscape handles special characters" {
    const allocator = std.testing.allocator;
    const escaped = try jsonEscape(allocator, "hello \"world\"\nnewline\\slash");
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("hello \\\"world\\\"\\nnewline\\\\slash", escaped);
}

test "isPrivateUrl identifies private addresses" {
    try std.testing.expect(isPrivateUrl("http://127.0.0.1:3000"));
    try std.testing.expect(isPrivateUrl("http://localhost:3000"));
    try std.testing.expect(isPrivateUrl("http://10.0.0.1:3000"));
    try std.testing.expect(isPrivateUrl("http://192.168.1.100:3000"));
    try std.testing.expect(isPrivateUrl("http://172.16.0.1:3000"));
    try std.testing.expect(isPrivateUrl("http://100.123.240.34:3000")); // Tailscale CGNAT
    try std.testing.expect(!isPrivateUrl("http://example.com"));
    try std.testing.expect(!isPrivateUrl("http://8.8.8.8"));
    try std.testing.expect(!isPrivateUrl("http://100.128.0.1")); // Outside CGNAT range
}

// ── SSRF variant tests ──────────────────────────────────────────

test "isPrivateUrl rejects decimal IP alias for localhost" {
    // 2130706433 = 127.0.0.1 in decimal — some HTTP clients resolve this
    try std.testing.expect(!isPrivateUrl("http://2130706433:3000"));
}

test "isPrivateUrl rejects IPv6 loopback" {
    try std.testing.expect(!isPrivateUrl("http://[::1]:3000"));
}

test "isPrivateUrl rejects zero IP" {
    try std.testing.expect(!isPrivateUrl("http://0.0.0.0:3000"));
}

test "isPrivateUrl boundary 172.15 is not private" {
    try std.testing.expect(!isPrivateUrl("http://172.15.0.1:3000"));
}

test "isPrivateUrl boundary 172.32 is not private" {
    try std.testing.expect(!isPrivateUrl("http://172.32.0.1:3000"));
}

test "isPrivateUrl Tailscale boundary 100.63 is not CGNAT" {
    try std.testing.expect(!isPrivateUrl("http://100.63.0.1:3000"));
}

test "a2a_call rejects URL with userinfo" {
    // http://admin:password@evil.com could bypass host checks
    const allocator = std.testing.allocator;
    var agents = [_]RemoteAgentConfig{
        .{ .name = "evil", .url = "http://admin:pass@evil.com" },
    };
    var t = A2aCallTool{ .remote_agents = &agents };
    const parsed = try root.parseTestArgs(
        \\{"agent":"evil","message":"hello"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

// ── Response parsing edge cases ─────────────────────────────────

test "parseA2aResponse handles empty body" {
    const allocator = std.testing.allocator;
    const result = try parseA2aResponse(allocator, "");
    try std.testing.expect(!result.success);
}

test "parseA2aResponse handles non-JSON body" {
    const allocator = std.testing.allocator;
    const result = try parseA2aResponse(allocator, "<html>502 Bad Gateway</html>");
    try std.testing.expect(!result.success);
}

test "parseA2aResponse handles JSON array instead of object" {
    const allocator = std.testing.allocator;
    const result = try parseA2aResponse(allocator, "[1,2,3]");
    try std.testing.expect(!result.success);
}

test "parseA2aResponse handles empty result object" {
    const allocator = std.testing.allocator;
    const result = try parseA2aResponse(allocator,
        \\{"jsonrpc":"2.0","id":"1","result":{}}
    );
    try std.testing.expect(!result.success);
}

test "parseA2aResponse handles completed with empty artifacts" {
    const allocator = std.testing.allocator;
    const result = try parseA2aResponse(allocator,
        \\{"jsonrpc":"2.0","id":"1","result":{"status":{"state":"completed"},"artifacts":[]}}
    );
    defer allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("(completed with no response text)", result.output);
}

test "parseA2aResponse handles working state" {
    const allocator = std.testing.allocator;
    const result = try parseA2aResponse(allocator,
        \\{"jsonrpc":"2.0","id":"1","result":{"id":"t1","status":{"state":"working"}}}
    );
    defer allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.startsWith(u8, result.output, "Task state: working"));
}

test "parseA2aResponse handles rejected state" {
    const allocator = std.testing.allocator;
    const result = try parseA2aResponse(allocator,
        \\{"jsonrpc":"2.0","id":"1","result":{"id":"t1","status":{"state":"rejected","message":{"parts":[{"kind":"text","text":"not authorized"}]}}}}
    );
    defer if (result.error_msg) |msg| allocator.free(msg);
    try std.testing.expect(!result.success);
}

test "parseA2aResponse handles error without message field" {
    const allocator = std.testing.allocator;
    const result = try parseA2aResponse(allocator,
        \\{"jsonrpc":"2.0","id":"1","error":{"code":-32600}}
    );
    try std.testing.expect(!result.success);
}

// ── JSON escape edge cases ──────────────────────────────────────

test "jsonEscape handles empty string" {
    const allocator = std.testing.allocator;
    const escaped = try jsonEscape(allocator, "");
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("", escaped);
}

test "jsonEscape handles control characters" {
    const allocator = std.testing.allocator;
    const escaped = try jsonEscape(allocator, "\x00\x01\x1f");
    defer allocator.free(escaped);
    // Should produce unicode escapes for each control char
    try std.testing.expect(escaped.len > 3);
    try std.testing.expect(std.mem.startsWith(u8, escaped, "\\u"));
}

test "jsonEscape preserves normal text" {
    const allocator = std.testing.allocator;
    const escaped = try jsonEscape(allocator, "hello world 123");
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("hello world 123", escaped);
}

// ── Configuration edge cases ────────────────────────────────────

test "a2a_call with no remote agents configured" {
    const allocator = std.testing.allocator;
    var t = A2aCallTool{};
    const parsed = try root.parseTestArgs(
        \\{"agent":"anything","message":"hello"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.error_msg) |msg| allocator.free(msg);
    try std.testing.expect(!result.success);
}

test "a2a_call agent lookup is case sensitive" {
    const allocator = std.testing.allocator;
    var agents = [_]RemoteAgentConfig{
        .{ .name = "Ironclaw", .url = "https://example.com" },
    };
    var t = A2aCallTool{ .remote_agents = &agents };
    const parsed = try root.parseTestArgs(
        \\{"agent":"ironclaw","message":"hello"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.error_msg) |msg| allocator.free(msg);
    try std.testing.expect(!result.success);
}

test "a2a_call HTTPS accepted for public URLs" {
    const allocator = std.testing.allocator;
    var agents = [_]RemoteAgentConfig{
        .{ .name = "secure", .url = "https://example.com" },
    };
    var t = A2aCallTool{ .remote_agents = &agents };

    test_send_override = testSendCompleted;
    defer {
        test_send_override = null;
    }

    const parsed = try root.parseTestArgs(
        \\{"agent":"secure","message":"hello"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer allocator.free(result.output);
    try std.testing.expect(result.success);
}

test "a2a_call HTTP error status returns failure" {
    const allocator = std.testing.allocator;
    var agents = [_]RemoteAgentConfig{
        .{ .name = "broken", .url = "http://10.0.0.1:3000" },
    };
    var t = A2aCallTool{ .remote_agents = &agents };

    test_send_override = testSend500;
    defer {
        test_send_override = null;
    }

    const parsed = try root.parseTestArgs(
        \\{"agent":"broken","message":"hello"}
    );
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.error_msg) |msg| allocator.free(msg);
    try std.testing.expect(!result.success);
}

/// Test helper: returns a completed A2A response.
fn testSendCompleted(
    allocator: std.mem.Allocator,
    _: []const u8,
    _: []const u8,
    _: []const []const u8,
    _: ?[]const u8,
) anyerror!http_util.HttpResponse {
    const resp_body =
        \\{"jsonrpc":"2.0","id":"1","result":{"id":"task-1","status":{"state":"completed"},"artifacts":[{"parts":[{"kind":"text","text":"Test response"}]}]}}
    ;
    return .{
        .status_code = 200,
        .body = try allocator.dupe(u8, resp_body),
    };
}

/// Test helper: returns a 500 error.
fn testSend500(
    allocator: std.mem.Allocator,
    _: []const u8,
    _: []const u8,
    _: []const []const u8,
    _: ?[]const u8,
) anyerror!http_util.HttpResponse {
    return .{
        .status_code = 500,
        .body = try allocator.dupe(u8, "Internal Server Error"),
    };
}
