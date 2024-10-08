# @a-type/auth

## 0.6.1

### Patch Changes

- 66120bb: fix validation

## 0.6.0

### Minor Changes

- 2bdbccf: fix (actually implement lol) password reset (oops)

## 0.5.4

### Patch Changes

- f1a8aa3: add partitioned cookie behavior

## 0.5.3

### Patch Changes

- 7562cf0: add secure to auxiliary cookies

## 0.5.2

### Patch Changes

- 9f1baa1: Maybe fix how headers are set on responses

## 0.5.1

### Patch Changes

- 901cab1: fix multiple cookie setting

## 0.5.0

### Minor Changes

- 938aad4: Change how refresh token is stored and sent

### Patch Changes

- 0e12f7c: Make auxiliary cookies follow session samesite policy

## 0.4.14

### Patch Changes

- b57091d: remove option to not send refresh token on session update
- 718cf62: allow setting samesite policy

## 0.4.13

### Patch Changes

- c1e376e: fix email interpolation

## 0.4.12

### Patch Changes

- fd1b834: Return responses on all refresh session code paths

## 0.4.11

### Patch Changes

- e5b7287: tweak token expiration behavior

## 0.4.10

### Patch Changes

- e59eefb: Improve refresh token failure cases
- 303a947: Increase default token timeouts and make them configurable. Expire access token cookie at token expiration time.

## 0.4.9

### Patch Changes

- 6d3baf0: Add a bunch of formatted errors

## 0.4.8

### Patch Changes

- 719a146: fix upserting password on existing user

## 0.4.7

### Patch Changes

- 78fe217: Fix issues with email login

## 0.4.6

### Patch Changes

- 139d1c0: Support adding login providers to existing users better

## 0.4.5

### Patch Changes

- b2e2a86: Fix email verification completion to accept formdata

## 0.4.4

### Patch Changes

- e4efb4d: More specific support for returnTo and close up some loopholes
- 15a9ab5: Support arbitrary appState passing during login

## 0.4.3

### Patch Changes

- fb96fac: Support path returnTo value

## 0.4.2

### Patch Changes

- 8662467: Fix returnTo for Oauth flow

## 0.4.1

### Patch Changes

- ada07bf: I give up - use get param for refresh token

## 0.4.0

### Minor Changes

- c1d68ad: Change sessionmanager method return format. Fix client domain for refresh token cookie

## 0.3.10

### Patch Changes

- a67b5aa: Use a cookie for refresh token

## 0.3.9

### Patch Changes

- 084bb86: Send refresh tokens from login endpoints

## 0.3.8

### Patch Changes

- 354687d: Refreshing session tokens

## 0.3.7

### Patch Changes

- fcf83f5: Improve errors thrown by session invalidation

## 0.3.6

### Patch Changes

- 8610d9d: Add generic email sending method

## 0.3.5

### Patch Changes

- 99f400e: Set jwt subject

## 0.3.4

### Patch Changes

- 3f0dbb2: make session validation less strict (jwts don't work this way...)

## 0.3.3

### Patch Changes

- c695295: Use cookie parser, iss/aud in verify

## 0.3.2

### Patch Changes

- 791c603: Allow undefined for getVerificationCode return

## 0.3.1

### Patch Changes

- a145059: Export missing tools

## 0.3.0

### Minor Changes

- 65cb7e6: Fix email login / signup flow

## 0.2.2

### Patch Changes

- 8af2aa0: Add session request

## 0.2.1

### Patch Changes

- 97e84a2: More flexible headers typings

## 0.2.0

### Minor Changes

- e4bcfd0: Rework sessions

## 0.1.4

### Patch Changes

- f0c9f22: Make createSession async

## 0.1.3

### Patch Changes

- 0293d9c: Fix typings on return type for user
- c6065e0: Support customized sessions better
