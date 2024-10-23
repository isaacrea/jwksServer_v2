# JWKS Server with JWT Authentication
A Python-based RESTful JWKS (JSON Web Key Set) server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs). It implements key expiry and rotation, includes an authentication endpoint, and handles the issuance of JWTs with expired keys based on a query parameter.
## Features
* **RSA Key Pair Generation**: Implements RSA key pair generation with unique `kid` and expiry timestamps.
* **JWKS Endpoint**: Serves public keys in JWKS format, excluding expired keys.
* **Authentication Endpoint**: Issues signed JWTs upon successful POST requests.
  * Supports issuing JWTs signed with expired keys when the `expired` query parameter is present.
* **Key Expiry and Rotation**:
  * Implements key expiry and excludes expired keys from JWKS.
  * Automatically rotates keys when existing keys are about to expire.
  * Cleans up old expired keys based on a retention period.
* **Database Handling**:
  * Uses an SQLite database to store private keys securely.
  * Database interactions use parameterized queries to prevent SQL injection.
* **Testing Suite**:
  * Includes comprehensive tests covering critical functionality.
  * Achieves over **80% code coverage**.
  * Tests cover edge cases, error handling, and key rotation logic.
* **Configuration Options**:
  * Allows customization of the database file and key rotation settings through `app.config`.
