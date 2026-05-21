---
name: concrete-cms-security
description: Apply this skill whenever you are writing, reviewing, or modifying PHP code for Concrete CMS (concrete5) — custom blocks, packages, single pages, dashboard or dialog or backend controllers, REST endpoints, Express entities, themes, attribute types, jobs, or anything in concrete/controllers, concrete/blocks, controllers/, blocks/, packages/, src/. Use it even when the user does not say "security" — for example, adding a new endpoint, accepting a POST parameter, rendering a user-supplied string, unserializing block config, fetching a URL server-side, or handling a file upload. Concrete CMS shipped 90+ CVEs over the past four years and the failure modes repeat — admin strings rendered raw, missing CSRF tokens on state-changing GETs, unserialize() on stored data, file uploads validated after writing, sequential IDs without per-object authz, type-juggling guard bypasses, OAuth handlers that skip account-state checks. This skill encodes the patterns behind those CVEs so you do not reproduce them.
---

# Concrete CMS Security

A skill for writing Concrete CMS code that does not reproduce the failure modes that have repeatedly become CVEs.

The patterns below are organized by **what happens if you get this wrong**, not by alphabet. The first section (CRITICAL) covers patterns that produced CVSS 7.0+ outcomes: remote code execution, privilege escalation, and authentication bypass. The second section (HIGH-FREQUENCY) covers patterns that produced the largest *count* of CVEs — mostly medium-severity, but the volume means at least one of them is relevant to almost any code change.

## When to use

Use this skill any time you touch Concrete CMS PHP. The trigger is the codebase, not the user's framing. If the user says "add a button that bulk-deletes selected logs" they have not mentioned security, but they are asking you to write exactly the kind of endpoint that produced CVE-2023-48652 in 2023 and CVE-2026-8409/8410/8411 in 2026 — three years of the same bug. Read this skill first, then write the code.

You do **not** need to read this skill for:
- Pure documentation, marketing copy, or release-note writing
- Frontend-only changes (CSS, JS that does not call new endpoints)
- Reading or summarizing existing code without modifying it

## Threat model

Three attacker profiles dominate the Concrete CMS CVE history. Design defensively against all three:

1. **The rogue admin / editor.** An attacker who already has elevated privileges in the CMS. The Concrete security team explicitly treats this as in-scope — most stored-XSS, deserialization, and path-traversal CVEs assume this attacker. Do not write code that says "this field is only edited by admins, so we trust it." Admin-supplied strings must still be HTML-encoded. Admin-supplied serialized data must not reach `unserialize()`. Admin-supplied file paths must be whitelist-validated.

2. **The unauthenticated attacker triggering a cross-site request against an authenticated victim.** This is the CSRF model. Every state-changing request must validate a CSRF token, including GET requests if they change state. The "victim is an admin" assumption is realistic — most CSRF chains in this codebase target admin sessions.

3. **The unauthenticated outsider hitting a public endpoint.** Dialog, frontend, and REST endpoints have repeatedly been reachable without authentication and have leaked file usage data, conversation messages, page metadata, and survey state. Treat every endpoint as unauthenticated until you have proven otherwise with an explicit permission check.

---

## CRITICAL patterns (produced CVSS 7.0+ CVEs)

If you violate any of these, a single mistake can produce a critical-severity vulnerability. Apply these *first*.

### C1. Never call `unserialize()` on data that has touched the database, the request, or block configuration

This is a repeat offender. CVE-2021-40102 (PHAR deserialization → file delete), CVE-2026-3452 (block config → RCE, CVSS 8.9), and CVE-2026-8135 (`ExpressEntryList` `filterFields` → RCE, CVSS 8.9) are all PHP object-injection bugs. Object instantiation during unserialize fires magic methods (`__wakeup`, `__destruct`, `__toString`) on attacker-chosen classes — in a framework this large, that is always a full RCE.

Rules:
- Do not use `unserialize()` on any value sourced from the database, the request, a file, or any other channel an admin or attacker could influence.
- If you must deserialize structured data, use `json_decode()` against a known schema and validate the resulting structure.
- `phar://` stream wrappers also deserialize. Never pass attacker-influenced paths to `file_exists`, `is_file`, `fopen`, `include`, or similar without filtering `phar:`.
- Block configuration columns that hold serialized PHP (`btTable_filterFields`, `btTable_columns`, etc.) are a smell. Flag them. Migrate to JSON.

### C2. Validate file uploads by content, not by extension — and validate *before* writing to disk

Concrete's file uploader has been the source of multiple RCEs:
- 2021 Fortbridge race-condition RCE: validations ran *after* the file was already written; an attacker raced the deletion of a rejected upload to execute a PHP web shell.
- CVE-2022-21829 (CVSS 9.8 / Concrete-team 8.0): the marketplace fetched zip files over HTTP and executed code from them.
- CVE-2026-8134 (CVSS 9.4): the file uploader allowed PHP code inside `.png` files because it only validated the extension; chained with a path-traversal field, this became authenticated RCE.

Rules:
- Reject by **content type and magic bytes**, not by file extension. A file with extension `.png` containing `<?php` must be rejected at validation, not after `move_uploaded_file()`.
- Validate **before** the bytes hit any path under the webroot, `application/`, or `DIR_PACKAGES`. If you must stream to disk first, stream to a path that is not executable by the web server.
- Avoid `uniqid()` and other non-cryptographic randomness for temp directory names. The Fortbridge RCE worked because `uniqid()` is predictable.
- Disable redirects on server-side fetches that will be executed or unpacked. Validate the final URL, not the original.
- For zip/archive ingestion, validate every entry name for path traversal before extraction. A `zip` containing `../../something.php` will write outside the intended directory.

### C3. Reject path traversal in any field that becomes a file path or template name

CVE-2021-40097, CVE-2021-40098 (path traversal → RCE), CVE-2022-30117 (traversal → arbitrary file delete), and CVE-2026-8134 (CVSS 9.4, the highest single score in the past year) all share a shape: a string field is concatenated into a file path that is later read, included, or used as a template.

Rules:
- Any field whose value will be concatenated into `require`, `include`, file read, or template render must reject `..`, absolute paths, null bytes, and stream wrappers (`phar://`, `file://`, `data://`, `gopher://`).
- Use a whitelist of allowed characters (`[A-Za-z0-9_-]`) where possible. Validate after normalization, not before — `..%2f` and `..%252f` are real attacks.
- Resolve the final path with `realpath()` and confirm it is still under the intended root before opening it.
- Treat template-name and custom-template fields as code, not data. The framework will literally include the resolved path.

### C4. State-changing GETs in package/marketplace/update flows have produced CSRF-to-RCE chains

CVE-2026-8140, CVE-2026-8417, CVE-2026-8421, CVE-2026-8426, and CVE-2026-8428 are five separate CSRF-to-RCE paths in marketplace install, update, and core-update endpoints (all CVSS 7.5). The pattern: `download()`, `do_update()`, `install_package()`, `prepare_remote_upgrade()` are GET routes guarded only by `canInstallPackages()` or `canUpgrade()`, with no CSRF token check. An attacker who could cause an authenticated admin to visit a page could force package installation or core upgrade — which is RCE.

Rules:
- Routes that install packages, upgrade the core, or write files under `DIR_PACKAGES` MUST validate a CSRF token. The permission check is necessary but not sufficient.
- If you write a new controller method that fetches, writes, or executes code based on a remote identifier (marketplace ID, package handle, version string), it is a CSRF-to-RCE target by default. Treat it as one.
- Reject GET for these routes entirely where possible. Require POST with a token tied to a specific action name.

### C5. Check authorization for the *action*, not just for the page

CVE-2026-8350 (CVSS 7.5) was privilege escalation to the Administrator group from the `bulk_user_assignment.php` dashboard page. The page-view permission was the only check, so any authenticated user with access to that dashboard page could add anyone (including themselves) to the Administrators group and remove legitimate admins. CVE-2021-22966 was the same pattern five years earlier — Editor-to-Admin escalation via the bulkupdate page.

Rules:
- View permission on a page does NOT imply mutation permission for every action exposed by that page. Each action method needs its own permission check that matches the *blast radius* of that action.
- Adding a user to the Administrators group should require Administrator-level authority, not "can see the bulk assignment dashboard."
- Group-membership mutations, permission-grant mutations, and user-role changes are privilege-escalation-adjacent. The check should be at least as strict as the privilege being granted.

### C6. Use strict comparisons and strict source validation; never trust loose-typed guards

CVE-2022-43690 was an authentication weakness in the legacy password algorithm because loose comparison (`==`) was used instead of strict comparison (`===`), enabling type-juggling attacks. CVE-2026-8135 (RCE, CVSS 8.9) bypassed a `_fromCIF === true` guard because the request was parsed with `json_decode()`, and `json_decode("true")` returns PHP boolean `true` — defeating the strict check on the value while leaving the request *source* unchecked.

Rules:
- Use `===` and `!==` for security comparisons. Never `==` in authentication, authorization, or guard code.
- Validate the *source* of the request (which controller path, which HTTP method, which user role), not just a field value. A "is this an internal CIF import" check that reads its own answer from the request body is not a check.
- For OAuth `state`, CSRF tokens, password hashes, and similar opaque tokens, use `hash_equals()` for constant-time comparison.
- Be wary of any value that can be transmitted as JSON: `true`, `false`, `null`, and numeric strings can collapse into PHP scalars that pass `===` against literals.

### C7. Re-authenticate for security-relevant account changes; check `uIsActive` on every auth path

CVE-2021-40101 (admin changing another user's password without re-prompt) and CVE-2026-8327 (raw POST array passed to `UserInfo::update()`, allowing password change without current-password verification and disabling per-user IP pinning) are the same lesson, five years apart. CVE-2026-7887 was an OAuth bypass where suspended accounts (`uIsActive=0`) could still obtain valid API tokens because the OAuth handler did not check account status.

Rules:
- Whitelist the fields you accept. Never pass `$_POST` or `$request->request->all()` straight to a model update.
- Password changes, email changes, 2FA changes, and session-hardening toggles require the current password (or a fresh authentication factor) verified server-side.
- `uIsActive` must be checked at every authentication path: username/password, OAuth callbacks, API token issuance, "remember me" cookies, password-reset flows. A suspended user must be unable to log in via any path.
- OAuth handlers in particular: treat them as full auth surfaces. Apply the same input validation, output encoding, account-status checks, and session-regeneration that you apply to username/password login. CVE-2022-43687 was missing session-ID rotation on OAuth login; CVE-2022-43693 was a missing `state` parameter enabling CSRF on the OAuth callback itself.

---

## HIGH-FREQUENCY patterns (produced the bulk of CVEs)

These produce mostly medium-severity bugs, but the *count* across four years is large enough that at least one is relevant to almost any code change.

### H1. HTML-encode every user-controllable string on output, including admin-supplied ones

This is the largest single bug class in Concrete CMS history. Every year, 5-15 stored-XSS CVEs ship. Examples from the past four years:
- 2022: dashboard breadcrumbs (43556), entity association names (43695), Microsoft tile icon (43688)
- 2023: API integration names, file tags, layout preset names, calendar color settings, group/role names, dashboard basics name
- 2024: file tags/descriptions (1245), Role Name (1247), Group Name (2179), calendar event name (7398), Image Editor Background Color (8291), Top Navigator Bar (8660), Next&Previous Nav (8661), Advanced File Search Filter (3178)
- 2025: Add Folder (0660), Home Folder (8573), Address attribute (3153), Conversation Messages (8571)
- 2026: Search block (3244), Switch Language (3242), Legacy Form (3240, 3241), OAuth integration name (8197, CVSS 7.3), height parameter (8203, CVSS 7.3), Atomik theme page name (8353), external-link cvName (8139)

The pattern is invariant: a string entered by an admin or editor is later rendered into HTML without escaping. "Only admins can set this" is not a defense — Concrete's security team explicitly treats rogue-admin XSS as in-scope.

Rules:
- Use `h()` (Concrete's HTML-escape helper) on every user-controllable string in a PHP template. Use `app('helper/text')->entities()` if `h()` is out of scope.
- Twig auto-escapes by default; this is one of the reasons 9.5.0 added Twig template support. Prefer Twig for new templates.
- Translation helpers do not sanitize. CVE-2026-8197 (CVSS 7.3) was XSS through `t()` because the integration name was used as a sprintf-style format string. Escape input *before* it enters a format string, or pass it as a separate argument and escape on output.
- HTML *attribute* injection is also XSS. CVE-2026-8245 was reflected XSS because a URL was interpolated into `href=""` without attribute encoding. Apply `h()` to attribute values.
- Numeric-looking fields are not safe by default. CVE-2026-8203 (CVSS 7.3) was XSS via a `height` parameter because the controller did not validate that it was a number. Cast or validate types explicitly.
- Any name/title/label field an editor controls is a potential XSS payload. Page names, file names, folder names, calendar event names, form question text, OAuth integration names, group/role names, Express entity names, layout preset names, search filter names — all of these have shipped stored XSS in this codebase.

### H2. Validate a CSRF token on every state-changing request, including GETs

CSRF was a known pattern by 2022 (CVE-2022-43693 missing OAuth state) and 2023 (CVE-2023-48652 logs delete, CVE-2023-48653 calendar event delete) — and it kept happening through CVE-2025-3153 (Address attribute), CVE-2026-2994 (Anti-Spam Allowlist), CVE-2026-7882 (inverted check on file deletion), and then the 20+ CSRF cluster in 9.5.1.

Rules:
- **State-changing GET routes are CSRF-vulnerable.** Do not assume "it's a GET, the browser won't preflight." `download()`, `do_update()`, `star()`, `rescan()`, `approveVersion()`, `addFavoriteFolder()`, `removeFavoriteFolder()`, `delete_all/submit`, `event/delete/submit` — all of these were GETs that mutated state and all became CVEs. If the route changes anything on the server, validate a token, regardless of HTTP method. Prefer requiring POST.
- **Emitting a token in the view does not validate it.** CVE-2026-8428 shipped a token in `local_available_update.php` but `do_update()` never checked it.
- **Check the result correctly.** CVE-2026-7882 was an *inverted* CSRF check: it threw on valid tokens and proceeded on invalid ones. Always test by removing the token from the request — the action must fail.
- Use `$this->app->make('token')->validate('action_name')`. Pair it with the emission point.
- New endpoints under `concrete/controllers/dialog`, `concrete/controllers/backend/file`, `concrete/controllers/single_page/dashboard/extend`, `concrete/controllers/single_page/dashboard/system/update`, and any package-related controller — audit the token validation explicitly. These subtrees have a poor track record.

### H3. Check per-object authorization on every load, not just at the controller entry point

CVE-2021-22951 and CVE-2021-22967 (IDOR via conversations/file access), CVE-2023-48653 (sequential event IDs explicitly called out), and then 10+ IDOR CVEs in 9.5.1: CVE-2026-6826, -8236, -8237, -8238, -8239, -7879, -7881, -7886, -8204, -8205, -8337, -8240, -8347. The pattern: a controller accepts an integer ID, looks up the corresponding object, and returns it without asking whether *this user* may see *this object*.

Rules:
- Every controller method that loads an object by ID must call the relevant permission check before returning data or mutating: `canViewFile()`, `canViewPage()`, `canView()` on the calendar, `canEditPageContents()`, etc.
- Existence-checking endpoints leak too. CVE-2026-8239 disclosed message existence via the rating endpoint. If the endpoint behaves differently for "exists but you can't see it" versus "doesn't exist," that is an information disclosure. Return 404 for both.
- Frontend endpoints under `/ccm/frontend/conversations`, `/ccm/system/dialogs/file/usage`, calendar `action_get_events`, and Express `exEntryID`-driven endpoints have a poor history. Permission checks here are not optional.
- For sequential numeric IDs that gate access, assume the attacker will enumerate. Prefer public-identifier strings (UUIDs) — Concrete itself moved Express Entry blocks from sequential IDs to public identifiers in 9.5.1 specifically because of this.

### H4. Validate and pin the destination of every server-side URL fetch

SSRF has been hit repeatedly: CVE-2021-22969 (DNS rebinding to cloud IAAS keys), CVE-2021-22970 (local IP imports), CVE-2021-40109 (big-endian/hex/octal IP variants, redirect-on-upload), CVE-2026-7890 (RSS Displayer SSRF).

Rules:
- Use the `Concrete\Core\Url\Validation` utilities added in 9.5.1 for new URL handling. The previous patchwork was insufficient.
- Resolve the hostname yourself, validate the resolved IP is not in any private range (RFC1918, link-local, loopback, IPv6 equivalents, IPv4-mapped IPv6, and cloud metadata IPs like 169.254.169.254), and connect using that IP (not the hostname) to defeat DNS rebinding.
- Reject non-decimal-dotted IP representations: hex, octal, big-endian integer.
- Disable redirects on server-side fetches, or validate the redirect target with the same rules.
- Block non-HTTP(S) schemes: `file://`, `phar://`, `gopher://`, `data://`, `dict://`, etc.

### H5. Do not leak server context through errors, debug pages, or XML processing

CVE-2022-43691 (whoops exposing `$_SERVER` and `$_ENV`, info disclosure of credentials and tokens), CVE-2022-43689 (XML entity expansion in SVG sanitization → DNS-based IP disclosure, an XXE variant).

Rules:
- Disable verbose error handlers (whoops, debug bars, stack traces) in production. Never include `$_SERVER`/`$_ENV` in any error output that could be reached over the network.
- When parsing XML or SVG, disable external entity loading: `libxml_disable_entity_loader(true)` (pre-8.0) or pass `LIBXML_NONET | LIBXML_NOENT=0` flags. Disable DOCTYPE processing if not needed.
- Catch exceptions at controller boundaries and return generic error responses to the client. Log the detail server-side.

### H6. Set secure file and directory permissions; don't create world-writable artifacts

CVE-2023-48648 (CVSS 6.6) was excessive directory permissions — Concrete created folders with `0777` because the permissions argument to `mkdir` was omitted or set too permissively. On shared hosting, this is local privilege escalation.

Rules:
- Always pass an explicit permissions argument to `mkdir`, `chmod`, `touch`. Use `0755` for directories and `0644` for files unless there is a documented reason otherwise.
- Never `chmod 0777` anything. If you find yourself wanting to, the right fix is changing ownership, not loosening permissions.

### H7. Keep dependencies patched and pinned

Dependency CVEs ship through Concrete every year: Guzzle (CVE-2023-29197), enshrined/svg-sanitized (CVE-2025-55166), Symfony PATH_INFO (CVE-2025-64500), historically Laminas/Zend Mail and league/oauth2-server.

Rules:
- Treat upstream CVEs in `composer.lock` as real CVEs for your site. Update on the same cadence as core.
- When you write new code that depends on third-party PHP libraries, prefer packages already in Concrete's composer tree to avoid pulling in new attack surface.

---

## Anti-patterns from real CVEs

If you find yourself writing code that matches any of these shapes, stop and reconsider.

**A. State-changing GET route with no token check** (CVE-2023-48652, CVE-2023-48653, CVE-2026-8411, and ~15 siblings):

```php
public function delete()
{
    if ($this->canEditPages()) {
        $this->deletePages($_GET['cIDs']);
    }
}
```

The permission check is necessary but not sufficient. Validate a CSRF token tied to a specific action name, and prefer POST for state changes.

**B. unserialize on database-stored block configuration** (CVE-2021-40102, CVE-2026-3452, CVE-2026-8135):

```php
$config = unserialize($this->btTable_filterFields);
```

Store configuration as JSON; parse with `json_decode` against a known schema. If you genuinely cannot migrate, use `unserialize($data, ['allowed_classes' => false])` and validate the result.

**C. IDOR via sequential integer ID** (CVE-2021-22967, CVE-2023-48653, CVE-2026-8236/8237/8238/8239 and several others):

```php
public function view($fID)
{
    $file = File::getByID($fID);
    return new JsonResponse($file->getJSONObject());
}
```

Check `canViewFile()` (or the analogous permission) before returning. Return 404 — not 403 — for objects the user cannot see, to avoid leaking existence. Prefer UUID identifiers in URLs.

**D. Admin-supplied string rendered raw** (every stored-XSS CVE in this list, ~30 of them):

```php
<h2><?= $integration->getName() ?></h2>
```

`<h2><?= h($integration->getName()) ?></h2>`, or use Twig.

**E. Page-view permission gating mutation actions** (CVE-2021-22966, CVE-2026-8350):

```php
public function bulkAssign()
{
    if (!$this->canAccess()) {
        throw new UserMessageException(t('Access Denied'));
    }
    // ... add arbitrary users to arbitrary groups ...
}
```

Check the action-specific permission. Adding a user to Administrators requires Administrator-level authority, not page-view authority.

**F. Path field concatenated into a template path** (CVE-2021-40097/40098, CVE-2022-30117, CVE-2026-8134):

```php
$template = $request->request->get('template');
include DIR_BASE . '/application/blocks/' . $type . '/' . $template . '.php';
```

Whitelist `$template` against `[A-Za-z0-9_-]+`, reject any value containing `.` or `/`, and `realpath()`-confirm the final path is under the intended root.

**G. File upload validated after writing to disk** (Fortbridge 2021 race-condition RCE, CVE-2026-8134):

```php
move_uploaded_file($_FILES['f']['tmp_name'], $dest);
if (!$this->validateExtension($dest)) {
    unlink($dest);
    throw new Exception('Bad file');
}
```

Validate `$_FILES['f']['tmp_name']` content and magic bytes *before* moving anywhere reachable. If you must inspect after writing, write to a non-executable path outside the webroot.

**H. Loose comparison or json_decode-based guard** (CVE-2022-43690, CVE-2026-8135):

```php
if ($request->request->get('_fromCIF') === true) {
    // skip validation
}
```

`json_decode("true")` returns PHP `true` and bypasses this. Validate the *source* of the request (controller path, internal call, authenticated caller), not a flag inside the request body.

**I. Raw $_POST to model update** (CVE-2021-40101, CVE-2026-8327):

```php
$userInfo->update($request->request->all());
```

Whitelist accepted fields. Require current-password verification for password/email/2FA changes.

**J. OAuth handler without state, session rotation, or active-account check** (CVE-2022-43687, CVE-2022-43693, CVE-2026-7887, CVE-2026-8197):

OAuth callbacks need: validated `state` parameter, regenerated session ID after successful auth, `uIsActive` check before issuing tokens, escaped integration metadata in any view.

---

## Pre-flight checklist

Before you finish writing any Concrete CMS PHP, walk this list. If you cannot answer all eight with "yes" or "not applicable," fix the code first.

1. **State change?** If this code mutates anything, is a CSRF token validated (not just emitted)? Does the check fail closed when the token is missing?
2. **Object load by ID?** Is there a per-object permission check before returning or mutating? Does the response avoid distinguishing "doesn't exist" from "you can't see it" when that distinction is unsafe?
3. **User-controllable string in output?** Is every interpolation HTML-escaped — including admin-supplied strings, strings inside attributes, and strings going through `t()`?
4. **Deserialization or template path?** Any `unserialize()`, `include`/`require` of a dynamic path, template-name field, or stream wrapper? If so: schema-validated, whitelisted, and not reachable from admin block config or untrusted input?
5. **File upload?** Validated by content and magic bytes before any write to a webroot-reachable path? No reliance on `uniqid()` for security?
6. **Server-side URL fetch?** Destination validated against private IPs, with DNS rebinding mitigated, non-HTTP schemes blocked, and redirects either disabled or re-validated?
7. **Account-state change?** Re-authentication required for password/email/2FA changes? Field whitelist on the update? `uIsActive` checked on every auth path including OAuth?
8. **Privilege boundary?** Is the permission check matched to the action's blast radius, not just to the page's view permission? Are security comparisons using `===` / `hash_equals()`?

## When in doubt

- **Mirror 9.5.1-era controllers**, not older ones. Many controllers under `concrete/controllers/dialog`, `concrete/controllers/backend/file`, and `concrete/controllers/single_page/dashboard/extend` were the *source* of CVEs and were rewritten in 9.5.1. Use the post-patch version as your model.
- **Default to Twig** for new view templates. Auto-escaping eliminates an entire class of mistake.
- **Slow down on Express, Conversations, Calendar, OAuth, Marketplace, and the file uploader.** These subsystems have been disproportionately responsible for high-severity CVEs across all four years.
- **If you are unsure whether a check is needed, add it.** The cost of a redundant `canView` is zero; the cost of a missing one is a CVE.
