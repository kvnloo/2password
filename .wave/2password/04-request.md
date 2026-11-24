# Bind requests and inject credentials at the approved destination

An approved destination must match the request the broker sends. Sources are upstream #6 (`2275541 ddb4d07 6b92175 92bd6de 5240dfc`) and #8’s descriptor seam (`19a041c 073452a`). Touch `src/request.ts` (`describe`, `requestWith`, `executeWithResolver`, `isPublicAddress`) and `test/request.test.ts`. Keep the #6 CLI wiring as reference for the leased command.

1. Bind the request to capability/version, agent, method and normalized target, rejecting queries, fragments and decoded parent traversal per RLP v1. Bind injection fields through the approved policy.
2. Implement internal HTTPS transport with vetted/pinned DNS, preserved TLS hostname checks, redirects disabled and bounded responses. Align configurable methods and headers with W1.
3. Keep output secret-free on success and failure. Use receipt-only output while W1 reconciles the response clause with GAP-4, and track full response parity explicitly. Expose the executor through the approved path in 07.

Acceptance: fake op and transport prove exact target/header delivery, no resolution for blocked targets, no redirect or alternate-address use, and no sentinel in successful or error receipts.

Branch `rlp/request`. Base `rlp/capability` while open, then `integration/rlp`. PR title “Bind requests and inject credentials at the approved destination”.
