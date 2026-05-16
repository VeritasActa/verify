// Cedar policy for Claude Code running under sb-runtime + nono.
// Conservative by default. Explicit allowlists for tool calls Claude Code
// actually needs; explicit deny for everything else.
//
// Scope: covers the governed actions emitted by Claude Code's built-in
// tools (Bash, Read, Write, Edit, Grep, Glob, WebFetch, WebSearch) plus
// the MCP tool_use action shape.

// ------------------------------------------------------------------ READS
// Allow reading inside the workspace and /tmp.
permit (
    principal is Agent::Principal,
    action == Agent::Action::"open",
    resource is Agent::File
) when {
    context.mode == "read" &&
    (resource.path like "/workspace/*" || resource.path like "/tmp/*")
};

// ------------------------------------------------------------------ WRITES
// Allow writes inside workspace only. /tmp is read-only so agents can't
// hide artefacts there.
permit (
    principal is Agent::Principal,
    action == Agent::Action::"open",
    resource is Agent::File
) when {
    context.mode == "write" &&
    resource.path like "/workspace/*"
};

// ------------------------------------------------------------------ EXEC
// Allow safe shell commands for common Claude Code workflows.
permit (
    principal is Agent::Principal,
    action == Agent::Action::"exec",
    resource
) when {
    context.command in [
        "ls", "cat", "grep", "rg", "find", "head", "tail", "wc",
        "git", "pytest", "npm", "npx", "yarn", "pnpm",
        "python", "python3", "node", "deno", "bun",
        "cargo", "rustc", "go", "gofmt"
    ]
};

// ------------------------------------------------------------------ NETWORK
// Allow HTTPS fetches to common developer domains Claude Code uses.
permit (
    principal is Agent::Principal,
    action == Agent::Action::"connect",
    resource is Agent::Endpoint
) when {
    context.tls == true &&
    (
        resource.host like "*.github.com" ||
        resource.host like "*.githubusercontent.com" ||
        resource.host like "*.anthropic.com" ||
        resource.host like "api.pypi.org" ||
        resource.host like "registry.npmjs.org"
    )
};

// ------------------------------------------------------------------ DENYS
// Block cloud metadata endpoints regardless of any allow above.
forbid (
    principal,
    action == Agent::Action::"connect",
    resource is Agent::Endpoint
) when {
    resource.host == "169.254.169.254" ||
    resource.host == "fd00:ec2::254" ||
    resource.host == "metadata.google.internal" ||
    resource.host like "metadata.*.internal"
};

// Block writes to system directories.
forbid (
    principal,
    action == Agent::Action::"open",
    resource is Agent::File
) when {
    context.mode == "write" &&
    (
        resource.path like "/etc/*" ||
        resource.path like "/usr/*" ||
        resource.path like "/root/*" ||
        resource.path like "/var/log/*" ||
        resource.path like "/sys/*" ||
        resource.path like "/proc/*"
    )
};

// Block reads of credential files even under /workspace (paranoid default).
forbid (
    principal,
    action == Agent::Action::"open",
    resource is Agent::File
) when {
    context.mode == "read" &&
    (
        resource.path like "*.pem" ||
        resource.path like "*id_rsa*" ||
        resource.path like "*id_ed25519*" ||
        resource.path like "*/.aws/credentials" ||
        resource.path like "*/.ssh/*" ||
        resource.path like "*/.netrc" ||
        resource.path like "*/secrets.*"
    )
};

// Block destructive shell commands.
forbid (
    principal,
    action == Agent::Action::"exec",
    resource
) when {
    context.command in ["rm", "dd", "mkfs", "shutdown", "reboot", "kill", "pkill"] ||
    (context.command == "git" && context.argv.contains("push") && context.argv.contains("--force"))
};
