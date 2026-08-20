# AI-driven Secret Scan Triage through Context Engineering

Secret scanning is a basic part of the Secure-Software Development Lifecycle (S-SDLC). In theory, this should be a simple process of running a list of regular expressions (regexes) against a code repository; many types of secrets, like AWS access keys or JWT tokens follow easily recognizable patterns, and secrets regex repositories are commonplace online. Yet in reality, functional and reliable secret scanning is no small task. Even the tightest regexes are liable to capture fragments of lengthy embedded blob strings, which can appear in a range of common file formats. Differentiating between a hard-coded string and a variable name can often prove challenging for repositories containing more than one coding language (as many do). Introducing exceptions and fine-tuning regexes to reduce false positives quickly becomes convoluted and frequently results in false negatives, so the right balance of strictness versus completeness is elusive. In practice, even state-of-the-art conventional secret scanners are extremely noisy, requiring tedious, painstaking human review. 

LLMs now provide a new approach, but at significant cost. Having an AI agent read through all code line-by-line may burn through more tokens than some organizations care to expend. Built-in code review features for GitHub can be pricey for organizations with a large code footprint, and are not necessarily geared for secret scanning specifically.

But what about a hybrid method that leverages conventional secret scanning tools in tandem with new LLM-driven techniques? How could this work in practice to obtain reliable results quickly and economically? 

If LLM-driven detection is not feasible, focus instead on LLM-driven triage. Consider the flow a human analyst would naturally follow when performing this task manually:
1. Scan the codebase
2. Review the findings for false positives
   - identify common patterns to mark true and false positives in batches
   - review remaining findings on a case-by-case basis
3. Alter the categorization and severity of unclassified findings 
4. Optionally check for live credentials # AI-driven Secret Scan Triage through Context Engineering

Secret scanning is a basic part of the Secure-Software Development Lifecycle (S-SDLC). In theory, this should be a simple process of running a list of regular expressions (regexes) against a code repository; many types of secrets, like AWS access keys or JWT tokens follow easily recognizable patterns, and secrets regex repositories are commonplace online. Yet in reality, functional and reliable secret scanning is no small task. Even the tightest regexes are liable to capture fragments of lengthy embedded blob strings, which can appear in a range of common file formats. Differentiating between a hard-coded string and a variable name can often prove challenging for repositories containing more than one coding language (as many do). Introducing exceptions and fine-tuning regexes to reduce false positives quickly becomes convoluted and frequently results in false negatives, so the right balance of strictness versus completeness is elusive. In practice, even state-of-the-art conventional secret scanners are extremely noisy, requiring tedious, painstaking human review. 

LLMs now provide a new approach, but at significant cost. Having an AI agent read through all code line-by-line may burn through more tokens than some organizations care to expend. Built-in code review features for GitHub can be pricey for organizations with a large code footprint, and are not necessarily geared for secret scanning specifically.

But what about a hybrid method that leverages conventional secret scanning tools in tandem with new LLM-driven techniques? How could this work in practice to obtain reliable results quickly and economically? 

If LLM-driven detection is not feasible, focus instead on LLM-driven triage. Consider the flow a human analyst would naturally follow when performing this task manually:
1. Scan the codebase
2. Review the findings for false positives
   - identify common patterns to mark true and false positives in batches
   - review remaining findings on a case-by-case basis
3. Alter the categorization and severity of unclassified findings 
4. Optionally check for live credentials 
5. Compile a report.


Steps 1 and 5 have long been scriptable, but steps 2 through 4 demand contextual reasoning, resisting conventional automation despite feeling like rote busy-work to a security practitioner. This is exactly the type of laborious process that can be offloaded to the LLM, but doing so reliably requires thoughtful context engineering: deliberately and strictly defining the scope, inputs, and encoded knowledge instead of relying on a simple prompt. [As noted by Jason Haddix in an insightful blog post](https://arcanum-sec.com/blog/hackbots/), models without context engineering are markedly less accurate. Note that, while context engineering is applied here for secret scan triage, the technique generalizes to any form of triage, or any number of complex workflows well-suited to AI.


## False Positive Rulesets

Run a secret detection tool like gitleaks locally on a body of code, then let the AI separate the signal from the noise by describing a series of checks, each enumerated in an MD file. Start with a false positive (FP) ruleset that describes common patterns a human analyst would easily pick up on but may be difficult to consistently match heuristically:

```
### RULE 1: SSRS VectorData in .rdl files
- **Condition**: `file` path ends with `.rdl` AND (`match` contains `VectorData` OR `match` is a long alphanumeric string in a map-polygon context)
- **Reason**: SQL Server Reporting Services (SSRS) `.rdl` report files contain VectorData elements with base64-encoded geographic polygon coordinates for map visualizations. These are publicly available geographic boundary data, not secrets.
- **FP reason string**: `"SSRS VectorData - geographic coordinates for map visualizations"`

### RULE 2: Config-imported variables on the RHS of an assignment
- **Condition**: File extension is a code file (`.cs`, `.java`, `.js`, `.ts`, `.py`, `.go`, `.rb`, `.php`, `.cpp`, `.c`, `.rs`, `.kt`, `.swift`, `.scala`) AND the right-hand side of `=` contains `Config`, `Configuration`, or `AppSettings` (case-insensitive) AND does NOT contain a quoted string literal on the RHS itself.
- **Reason**: These are variables assigned values READ FROM configuration files or objects, not hardcoded secrets. The variable name on the left may look secret-shaped to gitleaks, but the actual value comes from a config source at runtime.
- **FP reason string**: `"Configuration variable reference - reading from config, not a hardcoded secret"`
- **Pattern examples**:
  - `clientSecretValue = ConfigurationUtility.GetStringFromAppSettings(...)`
  - `token = Configuration.GetValue<string>("Auth:Token")`
  - `apiKey = Config["Auth:ApiKey"]`
  - `secret = appSettings.Value`
- **Exception**: If the RHS is a quoted literal (e.g. `secret = "AppSettingsBackupKey"`, where the value happens to contain "Config"), do not apply -- the value IS the literal.

### RULE 3: Kubernetes GitOps image-tag YAML entries
- **Condition**: `rule_id` is `generic-api-key` AND `file` path contains `image-tags` AND the file ends with `.yaml` or `.yml`.
- **Reason**: FluxCD / Kustomize / Argo image-tag manifests (e.g. `base/image-tags/image-tags.yaml`) contain key-value pairs like `serviceImageTag: "api-mm:x.x.xxxx"` -- the value is a Docker image tag / version string, not a secret. Gitleaks matches them because the shape looks API-key-like (long alphanumeric-with-dashes).
- **FP reason string**: `"Kubernetes GitOps image-tag YAML - version identifier, not a secret"`
- **Pattern examples**:
  - `serviceImageTag: "api-mm:x.x.xxxx"` (image tag - SAFE)
  - `gatewayImageTag: "api-abc123"` (image tag - SAFE)
- **Exception**: If an image-tag YAML somehow begins to contain a real API key (e.g. a Helm values file that mixes tags and secrets), this rule would silently dismiss it. Verify the file layout on any brand-new GitOps repo before trusting the rule.
```

The approach also allows for easy encoding of bits of organizational knowledge held by the human analysts:

```
### RULE 4: Okta tokens (organization does not use Okta)
- **Condition**: `rule_id` is `okta-token` OR the pattern is identified as an "Okta Token"
- **Reason**: This organization does not use Okta for authentication, so an Okta-shaped token is almost certainly a test fixture, a documentation example, or an unrelated string.
- **FP reason string**: `"Okta token - organization does not use Okta, likely false positive"`
- **Note**: Still inspect the match to confirm it is not a genuine token, but default to treating it as a false positive.
```

Note that LLMs benefit from clear, explicit instructions, where repetition enforces crucial directives:

```
### RULE 5: XML Value attribute is empty or a placeholder
- **Condition**: (file path ends with `.xml`, `.config`, `.token`, `.svl`, `.xml.bak` OR the snippet contains XML syntax indicators: `<`, `Name="`, `Value="`, `<?xml`) AND the `Value="..."` attribute on the flagged line is one of:
  - Empty string: `Value=""`
  - Placeholder pattern: `__PLACEHOLDER__`, `__VARIABLENAME__`, `{{token}}`, or any string starting with `OVERRIDE_IN_` (e.g. `OVERRIDE_IN_USER_CONFIG`)
  - Non-secret string: `"false"`, `"true"`, `"Development"`, a URL, or a display name
- **Reason**: XML configuration files (regardless of extension) often use templates with placeholder values that are replaced at deployment time. These placeholders are not secrets.
- **CRITICAL EXCLUSION**: Base64-encoded strings (especially those ending in `=` or `==`) are NOT placeholders - they are ENCODED values that anyone can decode. Base64 encoding is NOT encryption. Only apply this rule to truly empty values or explicit placeholder tokens (e.g. `__VAR__`).
- **How to check**:
  1. **Fast path**: Check the file extension first (`.xml`, `.config`, `.token`, `.svl`, `.xml.bak`).
  2. **Fallback**: If the extension doesn't match, check whether the snippet contains XML syntax.
  3. Verify the Value attribute is empty / placeholder / non-secret.
  4. **REJECT if base64**: If the value looks like base64 (alphanumeric with `/`, `+`, ending in `=`), this rule does NOT apply - treat it as uncertain or a true positive.
- **FP reason string**: `"XML Value attribute is empty/placeholder - no actual secret present"`
- **Pattern examples**:
  - `<add key="Password" value=""/>` (empty - SAFE)
  - `<add key="ApiKey" value="__APIKEY__"/>` (placeholder - SAFE)
  - `<add key="Secret" value="OVERRIDE_IN_USER_CONFIG"/>` (override marker - SAFE)
  - `<add key="Token" value="ZXhhbXBsZS1zZWNyZXQ="/>` (base64-encoded value - NOT SAFE)
  - `<add key="Password" value="ExampleFakePlaintextValue"/>` (plaintext - NOT SAFE)
```

Every false-positive dismissal rule carries a risk of introducing false negatives, so be sure to think them through carefully and test them extensively.

## Categorization rulesets

Most secret scanners assign categories to their findings, with a catch-all generic credential label typically being the most common. Breaking down that bucket is crucial to any triage process, so define another series of rules for categorization in a separate MD file:

```
### CAT-1: Azure Application Insights instrumentation key
- **Condition**: `match` contains `umentationKey` (gitleaks truncates `instrumentationKey` to the value portion) AND the file is a telemetry/eventflow config (`eventFlowConfig`, `ApplicationInsights`, etc.)
- **Note string**: `"Azure App Insights instrumentation key - real GUID but semi-public; data-injection risk; migrate to connection strings"`
- **Severity**: `LOW-MEDIUM`
- **Requires Pass 2**: no
- **Rationale**: The key identifies a telemetry workspace; anyone with it can inject fake telemetry but cannot read data. Microsoft has deprecated plain instrumentation keys in favor of connection strings.
- **Annotation command example**:
  `python parse_report.py <report.json> annotate --note "Azure App Insights instrumentation key - data-injection risk; migrate to connection strings" --severity LOW-MEDIUM --yes --confirmed-only --match-contains umentationKey`

### CAT-2: ASP.NET machineKey (decryptionKey / validationKey)
- **Condition**: `match` contains `machineKey` AND (`decryptionKey` OR `validationKey`)
- **Note string**: `"ASP.NET machineKey - used for FormsAuthentication cookie / ViewState encryption; exposure allows session forgery and ViewState tampering"`
- **Severity**: `MEDIUM`
- **Requires Pass 2**: no
- **Rationale**: These keys protect FormsAuthentication cookies and ViewState integrity. Exposure allows session forgery and ViewState tampering.
- **Annotation command example**:
  `python parse_report.py <report.json> annotate --note "ASP.NET machineKey - session forgery and ViewState tampering" --severity MEDIUM --yes --confirmed-only --match-contains machineKey`

### CAT-3: Angular environment encryption key (inputKey / outputKey)
- **Condition**: `match` contains `inputKey` or `outputKey` AND the file is an Angular environment file (`environment.ts`, `environment.development.ts`, `environment.qa.ts`, etc.)
- **Note string**: `"Angular environment encryption key - compiled into the browser JS bundle; key is publicly accessible to any user"`
- **Severity**: `HIGH`
- **Requires Pass 2**: no
- **Rationale**: Keys in Angular environment files are embedded in the JavaScript bundle served to browsers. Any user can extract them from the minified bundle, rendering the encryption ineffective. This is a terminal classification; the Pass 2 liveness check cannot change it.
- **Annotation command example**:
  `python parse_report.py <report.json> annotate --note "Angular environment encryption key - public in browser bundle" --severity HIGH --yes --confirmed-only --match-contains inputKey`
```

Building a robust set of false positive and categorization rules is an iterative process. Start by labeling a large batch of secret scanner findings, and noting any recurring patterns in a markdown file. Have the LLM review these data and draft initial rulesets to be reviewed by the human-in-the-loop. 

## Heuristic checks and post-AI enrichment 
It can be useful to divide rules into those which can be verified heuristically with scripts and those which need contextual reasoning. The former set can be implemented with helper scripts to reduce token usage and inject deterministic logic, whereas the latter require the LLM to inspect and reason about a code file or snippet. They can be positive identifiers, asserting findings as true positives, or negative identifiers, dismissing them as false positives.

Once findings have been filtered and categorized, they can be further enriched with liveness tests, especially for single-string credentials like SendGrid API keys and GitHub personal access tokens (PATs). JWTs are also good candidates, as their scope and freshness can be ascertained through the iss and exp fields. This analysis does not require AI, strictly speaking, but the LLM can assist by encoding these checks as scripts that would otherwise be time-consuming to implement.


## Dynamic workflows as JavaScript 
The review sequence can be defined in a dynamic workflow script, a feature that Anthropic recently introduced on May 28, 2026 for orchestrating complex, repeatable tasks. The workflow phases may look something like this:

```
export const meta = {
  name: 'secret-review',
  description: 'Repo secret scan: gitleaks x2 -> merge -> FP review -> CAT annotation -> Pass 2 liveness -> HTML + email',
  phases: [
    { title: 'Scan',           detail: 'Run gitleaks across all targeted code (in parallel)' },
    { title: 'Merge',          detail: 'Combine all results into a single unified report' },
    { title: 'FP Review',      detail: 'Apply FP rules to identify true and false positives' },
    { title: 'CAT Annotation', detail: 'Annotate confirmed findings with category notes' },
    { title: 'Liveness pass',  detail: 'Liveness verification for defined credentials' },
    { title: 'Report',         detail: 'Regenerate HTML and email the security team' },
  ],
}
```

Each phase must be described with ordered prompts. The scanning phase, for instance, would typically kick off a script that pulls the target code and scans it with a secret scanning utility, potentially covering separate code sources in parallel:

```
// -- Phase 1: Scan both code sources
// Pass args.reportPath to skip scanning and reuse an existing merged JSON.
// Example: {"reportPath":"/reports/combined_secret_scan_2026-07-21.json"}

let mergedPath = (args && args.reportPath) ? args.reportPath : null

if (!mergedPath) {
  phase('Scan')
  log('Running the secret scan on both code sources - total run time is typically 30-45 min.')

  const [source1Path, source2Path] = await Promise.all([
    agent(
      `Run the source 1 secret scan and return the path to the generated JSON report.

CRITICAL: Run the command in the FOREGROUND (run_in_background: false) and wait for it to finish.
Do NOT return early or set run_in_background: true - that will fail the workflow.

Steps:
  1. Run this Bash command with run_in_background: false and a 3600000 ms (60 min) timeout, then wait for it to finish:
       python ${SCANNER_ONE}
  2. The script prints "Report written to <path>" at the end. Look for that exact line.
  3. Return ONLY the absolute path to the .json report file. No other text.`,
      { label: 'source-1', phase: 'Scan' }
    ),
    agent(
      `Run the source 2 secret scan and return the path to the generated JSON report.

Steps:
  1. Run this command and wait for it to finish:
       python ${SCANNER_TWO}
  2. The script prints "Report written to <path>". Look for that line.
  3. Return ONLY the absolute path to the .json report file. No other text.`,
      { label: 'source-2', phase: 'Scan' }
    ),
  ])

  // ... merge source1Path and source2Path into a single report ...
}
```
	
The particulars of the workflow and helper scripts will depend on the needs and posture of the organization.


## The best of both worlds 

Everyone intuitively understands the raw potential of LLMs, but how and where to inject AI agents into existing workflows is not always apparent. Many organizations, especially large ones that can more easily absorb new costs, may opt for out-of-the-box solutions from the big AI providers or the numerous, proliferating AI-focused startups. Not unlike the SaaS security platforms that preceded them, these products are often expensive and generalized to the average use case, and may not account for the nuances of a given software shop. On the other hand, it can be tempting to try "vibe code" away persistent problems without deliberate context engineering, prompting LLMs to build complex workflow systems with minimal input or planning, believing that they will always arrive at the optimal solution. Instead of placing blind trust in the hot AI players, AppSec practitioners are better served by understanding the fundamentals of AI-assisted development themselves, such that they can embed their subject matter expertise and human intuition into evolving workflows -- this is how they can provide value in an increasingly AI-centric field. 
  
	
	
	
	
	

5. Compile a report.


Steps 1 and 5 have long been scriptable, but steps 2 through 4 demand contextual reasoning, resisting conventional automation despite feeling like rote busy-work to a security practitioner. This is exactly the type of laborious process that can be offloaded to the LLM, but doing so reliably requires thoughtful context engineering: deliberately and strictly defining the scope, inputs, and encoded knowledge instead of relying on a simple prompt. [As noted by Jason Haddix in an insightful blog post](https://arcanum-sec.com/blog/hackbots/), models without context engineering are markedly less accurate. Note that, while context engineering is applied here for secret scan triage, the technique generalizes to any form of triage, or any number of complex workflows well-suited to AI.


## False Positive Rulesets

Run a secret detection tool like gitleaks locally on a body of code, then let the AI separate the signal from the noise by describing a series of checks, each enumerated in an MD file. Start with a false positive (FP) ruleset that describes common patterns a human analyst would easily pick up on but may be difficult to consistently match heuristically:

```
### RULE 1: SSRS VectorData in .rdl files
- **Condition**: `file` path ends with `.rdl` AND (`match` contains `VectorData` OR `match` is a long alphanumeric string in a map-polygon context)
- **Reason**: SQL Server Reporting Services (SSRS) `.rdl` report files contain VectorData elements with base64-encoded geographic polygon coordinates for map visualizations. These are publicly available geographic boundary data, not secrets.
- **FP reason string**: `"SSRS VectorData - geographic coordinates for map visualizations"`

### RULE 2: Config-imported variables on the RHS of an assignment
- **Condition**: File extension is a code file (`.cs`, `.java`, `.js`, `.ts`, `.py`, `.go`, `.rb`, `.php`, `.cpp`, `.c`, `.rs`, `.kt`, `.swift`, `.scala`) AND the right-hand side of `=` contains `Config`, `Configuration`, or `AppSettings` (case-insensitive) AND does NOT contain a quoted string literal on the RHS itself.
- **Reason**: These are variables assigned values READ FROM configuration files or objects, not hardcoded secrets. The variable name on the left may look secret-shaped to gitleaks, but the actual value comes from a config source at runtime.
- **FP reason string**: `"Configuration variable reference - reading from config, not a hardcoded secret"`
- **Pattern examples**:
  - `clientSecretValue = ConfigurationUtility.GetStringFromAppSettings(...)`
  - `token = Configuration.GetValue<string>("Auth:Token")`
  - `apiKey = Config["Auth:ApiKey"]`
  - `secret = appSettings.Value`
- **Exception**: If the RHS is a quoted literal (e.g. `secret = "AppSettingsBackupKey"`, where the value happens to contain "Config"), do not apply -- the value IS the literal.

### RULE 3: Kubernetes GitOps image-tag YAML entries
- **Condition**: `rule_id` is `generic-api-key` AND `file` path contains `image-tags` AND the file ends with `.yaml` or `.yml`.
- **Reason**: FluxCD / Kustomize / Argo image-tag manifests (e.g. `base/image-tags/image-tags.yaml`) contain key-value pairs like `serviceImageTag: "api-mm:x.x.xxxx"` -- the value is a Docker image tag / version string, not a secret. Gitleaks matches them because the shape looks API-key-like (long alphanumeric-with-dashes).
- **FP reason string**: `"Kubernetes GitOps image-tag YAML - version identifier, not a secret"`
- **Pattern examples**:
  - `serviceImageTag: "api-mm:x.x.xxxx"` (image tag - SAFE)
  - `gatewayImageTag: "api-abc123"` (image tag - SAFE)
- **Exception**: If an image-tag YAML somehow begins to contain a real API key (e.g. a Helm values file that mixes tags and secrets), this rule would silently dismiss it. Verify the file layout on any brand-new GitOps repo before trusting the rule.
```

The approach also allows for easy encoding of bits of organizational knowledge held by the human analysts:

```
### RULE 4: Okta tokens (organization does not use Okta)
- **Condition**: `rule_id` is `okta-token` OR the pattern is identified as an "Okta Token"
- **Reason**: This organization does not use Okta for authentication, so an Okta-shaped token is almost certainly a test fixture, a documentation example, or an unrelated string.
- **FP reason string**: `"Okta token - organization does not use Okta, likely false positive"`
- **Note**: Still inspect the match to confirm it is not a genuine token, but default to treating it as a false positive.
```

Note that LLMs benefit from clear, explicit instructions, where repetition enforces crucial directives:

```
### RULE 5: XML Value attribute is empty or a placeholder
- **Condition**: (file path ends with `.xml`, `.config`, `.token`, `.svl`, `.xml.bak` OR the snippet contains XML syntax indicators: `<`, `Name="`, `Value="`, `<?xml`) AND the `Value="..."` attribute on the flagged line is one of:
  - Empty string: `Value=""`
  - Placeholder pattern: `__PLACEHOLDER__`, `__VARIABLENAME__`, `{{token}}`, or any string starting with `OVERRIDE_IN_` (e.g. `OVERRIDE_IN_USER_CONFIG`)
  - Non-secret string: `"false"`, `"true"`, `"Development"`, a URL, or a display name
- **Reason**: XML configuration files (regardless of extension) often use templates with placeholder values that are replaced at deployment time. These placeholders are not secrets.
- **CRITICAL EXCLUSION**: Base64-encoded strings (especially those ending in `=` or `==`) are NOT placeholders - they are ENCODED values that anyone can decode. Base64 encoding is NOT encryption. Only apply this rule to truly empty values or explicit placeholder tokens (e.g. `__VAR__`).
- **How to check**:
  1. **Fast path**: Check the file extension first (`.xml`, `.config`, `.token`, `.svl`, `.xml.bak`).
  2. **Fallback**: If the extension doesn't match, check whether the snippet contains XML syntax.
  3. Verify the Value attribute is empty / placeholder / non-secret.
  4. **REJECT if base64**: If the value looks like base64 (alphanumeric with `/`, `+`, ending in `=`), this rule does NOT apply - treat it as uncertain or a true positive.
- **FP reason string**: `"XML Value attribute is empty/placeholder - no actual secret present"`
- **Pattern examples**:
  - `<add key="Password" value=""/>` (empty - SAFE)
  - `<add key="ApiKey" value="__APIKEY__"/>` (placeholder - SAFE)
  - `<add key="Secret" value="OVERRIDE_IN_USER_CONFIG"/>` (override marker - SAFE)
  - `<add key="Token" value="ZXhhbXBsZS1zZWNyZXQ="/>` (base64-encoded value - NOT SAFE)
  - `<add key="Password" value="ExampleFakePlaintextValue"/>` (plaintext - NOT SAFE)
```

Every false-positive dismissal rule carries a risk of introducing false negatives, so be sure to think them through carefully and test them extensively.

## Categorization rulesets

Most secret scanners assign categories to their findings, with a catch-all generic credential label typically being the most common. Breaking down that bucket is crucial to any triage process, so define another series of rules for categorization in a separate MD file:

```
### CAT-1: Azure Application Insights instrumentation key
- **Condition**: `match` contains `umentationKey` (gitleaks truncates `instrumentationKey` to the value portion) AND the file is a telemetry/eventflow config (`eventFlowConfig`, `ApplicationInsights`, etc.)
- **Note string**: `"Azure App Insights instrumentation key - real GUID but semi-public; data-injection risk; migrate to connection strings"`
- **Severity**: `LOW-MEDIUM`
- **Requires Pass 2**: no
- **Rationale**: The key identifies a telemetry workspace; anyone with it can inject fake telemetry but cannot read data. Microsoft has deprecated plain instrumentation keys in favor of connection strings.
- **Annotation command example**:
  `python parse_report.py <report.json> annotate --note "Azure App Insights instrumentation key - data-injection risk; migrate to connection strings" --severity LOW-MEDIUM --yes --confirmed-only --match-contains umentationKey`

### CAT-2: ASP.NET machineKey (decryptionKey / validationKey)
- **Condition**: `match` contains `machineKey` AND (`decryptionKey` OR `validationKey`)
- **Note string**: `"ASP.NET machineKey - used for FormsAuthentication cookie / ViewState encryption; exposure allows session forgery and ViewState tampering"`
- **Severity**: `MEDIUM`
- **Requires Pass 2**: no
- **Rationale**: These keys protect FormsAuthentication cookies and ViewState integrity. Exposure allows session forgery and ViewState tampering.
- **Annotation command example**:
  `python parse_report.py <report.json> annotate --note "ASP.NET machineKey - session forgery and ViewState tampering" --severity MEDIUM --yes --confirmed-only --match-contains machineKey`

### CAT-3: Angular environment encryption key (inputKey / outputKey)
- **Condition**: `match` contains `inputKey` or `outputKey` AND the file is an Angular environment file (`environment.ts`, `environment.development.ts`, `environment.qa.ts`, etc.)
- **Note string**: `"Angular environment encryption key - compiled into the browser JS bundle; key is publicly accessible to any user"`
- **Severity**: `HIGH`
- **Requires Pass 2**: no
- **Rationale**: Keys in Angular environment files are embedded in the JavaScript bundle served to browsers. Any user can extract them from the minified bundle, rendering the encryption ineffective. This is a terminal classification; the Pass 2 liveness check cannot change it.
- **Annotation command example**:
  `python parse_report.py <report.json> annotate --note "Angular environment encryption key - public in browser bundle" --severity HIGH --yes --confirmed-only --match-contains inputKey`
```

Building a robust set of false positive and categorization rules is an iterative process. Start by labeling a large batch of secret scanner findings, and noting any recurring patterns in a markdown file. Have the LLM review these data and draft initial rulesets to be reviewed by the human-in-the-loop. 

## Heuristic checks and post-AI enrichment 
It can be useful to divide rules into those which can be verified heuristically with scripts and those which need contextual reasoning. The former set can be implemented with helper scripts to reduce token usage and inject deterministic logic, whereas the latter require the LLM to inspect and reason about a code file or snippet. They can be positive identifiers, asserting findings as true positives, or negative identifiers, dismissing them as false positives.

Once findings have been filtered and categorized, they can be further enriched with liveness tests, especially for single-string credentials like SendGrid API keys and GitHub personal access tokens (PATs). JWTs are also good candidates, as their scope and freshness can be ascertained through the iss and exp fields. This analysis does not require AI, strictly speaking, but the LLM can assist by encoding these checks as scripts that would otherwise be time-consuming to implement.


## Dynamic workflows as JavaScript 
The review sequence can be defined in a dynamic workflow script, a feature that Anthropic recently introduced on May 28, 2026 for orchestrating complex, repeatable tasks. The workflow phases may look something like this:

```
export const meta = {
  name: 'secret-review',
  description: 'Repo secret scan: gitleaks x2 -> merge -> FP review -> CAT annotation -> Pass 2 liveness -> HTML + email',
  phases: [
    { title: 'Scan',           detail: 'Run gitleaks across all targeted code (in parallel)' },
    { title: 'Merge',          detail: 'Combine all results into a single unified report' },
    { title: 'FP Review',      detail: 'Apply FP rules to identify true and false positives' },
    { title: 'CAT Annotation', detail: 'Annotate confirmed findings with category notes' },
    { title: 'Liveness pass',  detail: 'Liveness verification for defined credentials' },
    { title: 'Report',         detail: 'Regenerate HTML and email the security team' },
  ],
}
```

Each phase must be described with ordered prompts. The scanning phase, for instance, would typically kick off a script that pulls the target code and scans it with a secret scanning utility, potentially covering separate code sources in parallel:

```
// -- Phase 1: Scan both code sources
// Pass args.reportPath to skip scanning and reuse an existing merged JSON.
// Example: {"reportPath":"/reports/combined_secret_scan_2026-07-21.json"}

let mergedPath = (args && args.reportPath) ? args.reportPath : null

if (!mergedPath) {
  phase('Scan')
  log('Running the secret scan on both code sources - total run time is typically 30-45 min.')

  const [source1Path, source2Path] = await Promise.all([
    agent(
      `Run the source 1 secret scan and return the path to the generated JSON report.

CRITICAL: Run the command in the FOREGROUND (run_in_background: false) and wait for it to finish.
Do NOT return early or set run_in_background: true - that will fail the workflow.

Steps:
  1. Run this Bash command with run_in_background: false and a 3600000 ms (60 min) timeout, then wait for it to finish:
       python ${SCANNER_ONE}
  2. The script prints "Report written to <path>" at the end. Look for that exact line.
  3. Return ONLY the absolute path to the .json report file. No other text.`,
      { label: 'source-1', phase: 'Scan' }
    ),
    agent(
      `Run the source 2 secret scan and return the path to the generated JSON report.

Steps:
  1. Run this command and wait for it to finish:
       python ${SCANNER_TWO}
  2. The script prints "Report written to <path>". Look for that line.
  3. Return ONLY the absolute path to the .json report file. No other text.`,
      { label: 'source-2', phase: 'Scan' }
    ),
  ])

  // ... merge source1Path and source2Path into a single report ...
}
```
	
The particulars of the workflow and helper scripts will depend on the needs and posture of the organization.


## The best of both worlds 

Everyone intuitively understands the raw potential of LLMs, but how and where to inject AI agents into existing workflows is not always apparent. Many organizations, especially large ones that can more easily absorb new costs, may opt for out-of-the-box solutions from the big AI providers or the numerous, proliferating AI-focused startups. Not unlike the SaaS security platforms that preceded them, these products are often expensive and generalized to the average use case, and may not account for the nuances of a given software shop. On the other hand, it can be tempting to try "vibe code" away persistent problems without deliberate context engineering, prompting LLMs to build complex workflow systems with minimal input or planning, believing that they will always arrive at the optimal solution. Instead of placing blind trust in the hot AI players, AppSec practitioners are better served by understanding the fundamentals of AI-assisted development themselves, such that they can embed their subject matter expertise and human intuition into evolving workflows -- this is how they can provide value in an increasingly AI-centric field. 
