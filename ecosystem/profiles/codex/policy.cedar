// Cedar policy for OpenAI Codex CLI — stricter default than claude-code.
// Default-deny on exec; operator narrows allowlist per project.

// Read-only in workspace + /tmp
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

// Exec is DENY-BY-DEFAULT. Project-specific operators must explicitly
// extend this allowlist. Only the safest inspection commands are allowed.
permit (
    principal is Agent::Principal,
    action == Agent::Action::"exec",
    resource
) when {
    context.command in ["ls", "cat", "grep", "rg", "find", "head", "tail", "wc"]
};

// Network: OpenAI API + package managers only.
permit (
    principal is Agent::Principal,
    action == Agent::Action::"connect",
    resource is Agent::Endpoint
) when {
    context.tls == true &&
    (
        resource.host like "*.openai.com" ||
        resource.host like "api.github.com" ||
        resource.host like "*.githubusercontent.com" ||
        resource.host like "api.pypi.org" ||
        resource.host like "registry.npmjs.org"
    )
};

// Universal denies
forbid (
    principal,
    action == Agent::Action::"connect",
    resource is Agent::Endpoint
) when {
    resource.host == "169.254.169.254" ||
    resource.host == "metadata.google.internal" ||
    resource.host == "fd00:ec2::254" ||
    resource.host like "metadata.*.internal"
};

forbid (
    principal,
    action == Agent::Action::"open",
    resource is Agent::File
) when {
    (context.mode == "write" && (resource.path like "/etc/*" || resource.path like "/usr/*" || resource.path like "/root/*" || resource.path like "/var/log/*")) ||
    (context.mode == "read" && (resource.path like "*.pem" || resource.path like "*id_rsa*" || resource.path like "*id_ed25519*" || resource.path like "*/.aws/credentials" || resource.path like "*/.ssh/*" || resource.path like "*/.netrc"))
};

forbid (
    principal,
    action == Agent::Action::"exec",
    resource
) when {
    context.command in ["rm", "dd", "mkfs", "shutdown", "reboot", "kill", "pkill", "chmod", "chown"]
};
