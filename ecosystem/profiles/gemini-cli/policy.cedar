// Cedar policy for Google Gemini CLI. Read-review default with scoped shell.

permit (
    principal is Agent::Principal,
    action == Agent::Action::"open",
    resource is Agent::File
) when {
    context.mode == "read" &&
    (resource.path like "/workspace/*" || resource.path like "/tmp/*")
};

permit (
    principal is Agent::Principal,
    action == Agent::Action::"open",
    resource is Agent::File
) when {
    context.mode == "write" && resource.path like "/workspace/*"
};

permit (
    principal is Agent::Principal,
    action == Agent::Action::"exec",
    resource
) when {
    context.command in [
        "ls", "cat", "grep", "rg", "find", "head", "tail", "wc",
        "git", "pytest", "npm", "node", "python", "python3", "go"
    ]
};

permit (
    principal is Agent::Principal,
    action == Agent::Action::"connect",
    resource is Agent::Endpoint
) when {
    context.tls == true &&
    (
        resource.host like "*.googleapis.com" ||
        resource.host like "generativelanguage.googleapis.com" ||
        resource.host like "*.google.com" ||
        resource.host like "api.github.com" ||
        resource.host like "*.githubusercontent.com" ||
        resource.host like "api.pypi.org" ||
        resource.host like "registry.npmjs.org"
    )
};

forbid (
    principal,
    action == Agent::Action::"connect",
    resource is Agent::Endpoint
) when {
    resource.host == "169.254.169.254" ||
    resource.host == "metadata.google.internal" ||
    resource.host == "fd00:ec2::254"
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
    context.command in ["rm", "dd", "mkfs", "shutdown", "reboot", "kill", "pkill"]
};
