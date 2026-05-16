// Cedar policy for Cursor running under sb-runtime + nono.
// Baseline mirrors claude-code; adds Cursor-specific network allowlist.

// Reads in workspace + /tmp
permit (
    principal is Agent::Principal,
    action == Agent::Action::"open",
    resource is Agent::File
) when {
    context.mode == "read" &&
    (resource.path like "/workspace/*" || resource.path like "/tmp/*")
};

// Writes in workspace only
permit (
    principal is Agent::Principal,
    action == Agent::Action::"open",
    resource is Agent::File
) when {
    context.mode == "write" && resource.path like "/workspace/*"
};

// Safe shell allowlist
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

// Cursor-specific network allowlist (extends the developer-domain set)
permit (
    principal is Agent::Principal,
    action == Agent::Action::"connect",
    resource is Agent::Endpoint
) when {
    context.tls == true &&
    (
        resource.host like "*.github.com" ||
        resource.host like "*.githubusercontent.com" ||
        resource.host like "*.cursor.com" ||
        resource.host like "*.cursor.sh" ||
        resource.host like "api.pypi.org" ||
        resource.host like "registry.npmjs.org"
    )
};

// Universal denies (identical to claude-code profile)
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

forbid (
    principal,
    action == Agent::Action::"exec",
    resource
) when {
    context.command in ["rm", "dd", "mkfs", "shutdown", "reboot", "kill", "pkill"]
};
