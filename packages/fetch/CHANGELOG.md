# @a-type/auth-fetch

## 2.1.2

### Patch Changes

- b6e1d71: Remove problematic heuristic

## 2.1.1

### Patch Changes

- fa874f1: adjust refresh failure heuristics

## 2.1.0

### Minor Changes

- 566b6fa: Await refresh before starting requests

## 2.0.2

### Patch Changes

- da5057d: Add error capture for refresh failures

## 2.0.1

### Patch Changes

- b1388e1: Better refresh failure handling

## 2.0.0

### Major Changes

- dd14780: Constructing the fetch wrapper now requires specifying a logout endpoint. Fetch will auto-logout when it detects a faulty session cookie to create a blank slate for the user to log in again.

## 1.0.2

### Patch Changes

- 660277c: restructure built files
