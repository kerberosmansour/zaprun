// zaprun-rule-name: reflected-xss-generic
// cwe: CWE-79
// risk: medium
// confidence: medium
// surface: web
// match: reflected-user-input
// generality: Detects a reflected user-controlled marker in HTTP responses.
function scanNode(message) {
  return message.getResponseBody().includes("reflected-user-input");
}
