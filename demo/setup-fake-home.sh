#!/bin/bash
# Creates a fake home directory with dummy credentials for the demo.
# Run this once before running run-demo.sh.

FAKE_HOME="/tmp/safe-shell-demo"
mkdir -p "$FAKE_HOME/.aws" "$FAKE_HOME/.ssh" "$FAKE_HOME/.docker" "$FAKE_HOME/.gnupg" "$FAKE_HOME/.kube"

cat > "$FAKE_HOME/.aws/credentials" << 'EOF'
[default]
aws_access_key_id     = AKIAFAKEKEY1234567890
aws_secret_access_key = FakeSecretKey1234567890abcdefghijklmnopqrs

[production]
aws_access_key_id     = AKIAFAKEPROD987654321
aws_secret_access_key = FakeProdSecret0987654321zyxwvutsrqponmlk
region                = us-east-1
EOF

cat > "$FAKE_HOME/.ssh/id_rsa" << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
THIS/IS/NOT/A/REAL/KEY/IT/IS/FOR/DEMO/ONLY/SAFE
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
-----END OPENSSH PRIVATE KEY-----
EOF

cat > "$FAKE_HOME/.docker/config.json" << 'EOF'
{
  "auths": {
    "registry.example.com": {
      "auth": "ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk"
    }
  }
}
EOF

cat > "$FAKE_HOME/.kube/config" << 'EOF'
apiVersion: v1
kind: Config
users:
- name: admin
  user:
    token: fake-bearer-token-1234567890abcdef
EOF

echo "Fake home directory created at $FAKE_HOME"
echo "Run: bash demo/run-demo.sh"
