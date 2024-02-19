# auth

My personal library for API authentication.

Designed to plug into itty-router based servers.

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
