# Multipart/Related Binding Model

## Normative Structure

3GPP TS 29.500 clause 5.2.2.8 and TS 29.502 clause 6.1.2.2 specify that SBI requests
and responses may carry a `multipart/related` media type when binary payload(s) accompany
JSON metadata.

A multipart message comprises:
1. A root JSON part with `Content-Type: application/json` containing the metadata structure
   (e.g., `SmContextCreateData`, `SmContextCreatedData`, `SmContextUpdateData`).
2. One or more binary parts referenced from the JSON structure:
   - **N1 SM Information**: `Content-Type: application/vnd.3gpp.5gnas`
   - **N2 SM Information**: `Content-Type: application/vnd.3gpp.ngap`

## Content-ID Binding vs. Positional Zipping

### Strict Prohibition of Positional Zip

3GPP specifications define that binary parts are referenced by explicit `Content-ID`
(using `RefToBinaryData.contentId`).
- An implementation **MUST NOT** bind binary parts by array position (e.g., `zip(references, parts)`).
- Parts may appear in any order in the MIME body. The first binary part is not necessarily
  the N1 part, nor is the second part necessarily N2.

### Deterministic Binding Rules

1. **Normalization of Content-ID**:
   - The JSON reference provides a `contentId` string (e.g., `"n1msg"`).
   - The MIME part header contains `Content-ID: <n1msg>` or `Content-ID: n1msg`.
   - The matching comparison strips optional angle brackets (`<` and `>`) and whitespace.
2. **Explicit Match**:
   - If exactly one multipart part matches `n1SmMsg.contentId`:
     `semantic_role = "N1_SM_INFO"`, `reference_basis = "EXPLICIT_CONTENT_ID"`.
   - If exactly one multipart part matches `n2SmInfo.contentId`:
     `semantic_role = "N2_SM_INFO"`, `reference_basis = "EXPLICIT_CONTENT_ID"`.
3. **Root Part**:
   - The part with `Content-Type: application/json` (or Content-ID `"jsonData"`):
     `semantic_role = "JSON_METADATA"`, `reference_basis = "ROOT_JSON"`.
4. **Unreferenced Part**:
   - Any part not referenced by JSON and not root JSON:
     `semantic_role = "UNRESOLVED"`, `reference_basis = "UNREFERENCED"`.

## Ambiguous and Missing Multipart Evidence

- **Missing Content-ID**: If the JSON structure references a `contentId` that does not exist
  among the multipart parts, the event preserves the reference, sets no part, and records:
  `referenced Content-ID '<cid>' has no matching multipart part`.
- **Duplicate Content-ID**: If multiple body parts carry identical `Content-ID` values,
  binding is ambiguous. Matching parts are marked `semantic_role = "UNRESOLVED"`,
  `reference_basis = "AMBIGUOUS_CONTENT_ID"`, and a limitation is recorded.

## Binary Boundary Discipline

Per CoreNet Skill architecture rules:
- **Raw binary payload bytes MUST NEVER be persisted.**
- NAS bytes, NGAP transfer bytes, hex dumps, and base64 strings are strictly forbidden
  in committed event outputs.
- Only metadata (`content_id`, `content_type`, `length`, `semantic_role`, `reference_basis`)
  is preserved.
