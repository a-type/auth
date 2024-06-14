# auth

My personal library for API authentication.

Designed to plug into itty-router based servers.

Made for me since I keep making new projects that need auth. It's so particular and poorly documented you probably won't find it useful, but it's just easier to make this stuff open source.

## Users

This library has some opinions about what a user is.

A user has:

- id
- email
- fullName (a formal name, provided by OAuth provider or the user themselves)
- friendlyName (an informal, changeable name shown to other people)

## Login flows

This library powers OAuth-based login flows with specified providers.

It also enables an email login flow with email+password, including email verification and password resets.

### Email flow

The email flow is fairly opinionated.

First, submit a request handled by `handlers.handleSendEmailVerificationRequest` to verify the user owns the email. They must provide email and name (fullName).

This creates an email verification token in the database and sends them an email with a code.

The user then clicks the link in the email to return to the app with the code. Upon presenting the code, they must then choose a password. The code and password are sent back to the server to the `handlers.handleVerifyEmailRequest` handler. This creates the user's account and identity on the server and sets up email login.

Password reset works fairly similarly - send a request to send the password reset email, get the code, return and set a new password.

## Client

`@a-type/auth-client` includes tools for React-based clients to integrate quickly with a backend powered by `@a-type/auth`.

Use `createFetch` to make a `fetch`-alike which automatically refreshes the session and retries the request upon session expiration.

By default it expects a session expiration response to be a 401 with a header `x-auth-error: session-expired`. It's up to your server integration to provide this with the way it handles and responds after a `Session expired` AuthError. You can do this relatively easily by just returning `AuthError.toResponse()`. Or you can override the logic for deciding session expiration with the fetch params.

The client lib also contains several React components using my UI library which cover the forms required for login/signup and password resets. My UI library is a peer dep. If you're not me and reading this, that's probably annoying. But if you are me, you're already using my UI library, so...

Yeah, sorry, this isn't exactly a generic auth solution! I just make a lot of new projects and I hate reinventing the wheel.
