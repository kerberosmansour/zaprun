function getMetadata() {
  return {
    id: "cwe-79-dom-taint-flow",
    name: "DOM taint source to sink heuristic",
    description: "Flags JavaScript responses that contain common DOM taint sources and unsafe sinks.",
    cweId: 79,
    risk: "Medium",
    confidence: "Low"
  };
}

function scanNode(ps, msg) {
  var body = String(msg.getResponseBody());
  var hasSource = /(location\.(hash|search|href)|postMessage|localStorage|sessionStorage)/.test(body);
  var hasSink = /(innerHTML|outerHTML|document\.write|eval\s*\(|Function\s*\()/.test(body);
  if (hasSource && hasSink) {
    ps.raiseAlert(2, 1, "DOM taint source to sink heuristic", "Possible DOM XSS candidate", msg.getRequestHeader().getURI().toString(), "", "", "Review the JavaScript data flow.", body.substring(0, 200), 79, 0, msg);
  }
}

