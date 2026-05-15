// zaprun-rule-name: acme-admin-reflection
// cwe: CWE-79
// risk: medium
// confidence: medium
// surface: web
// match: reflected-user-input
// app-literal: /private/acme-admin
// generality: Target-owned detector for one private route.
function scanNode(message) {
  return message.getRequestHeader().includes("/private/acme-admin")
    && message.getResponseBody().includes("reflected-user-input");
}
