// zaprun-rule-name: missing-metadata
// match: reflected-user-input
function scanNode(message) {
  return message.getResponseBody().includes("reflected-user-input");
}
