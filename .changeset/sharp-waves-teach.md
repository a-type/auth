---
"@a-type/auth-fetch": major
---

Constructing the fetch wrapper now requires specifying a logout endpoint. Fetch will auto-logout when it detects a faulty session cookie to create a blank slate for the user to log in again.
