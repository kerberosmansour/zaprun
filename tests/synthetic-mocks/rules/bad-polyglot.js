// zaprun-rule-name: bad-polyglot
// cwe: CWE-79
// risk: medium
// confidence: medium
// surface: web
// match: reflected-user-input
// generality: Deliberately unsafe fixture.
Polyglot.eval("js", "response.body");
