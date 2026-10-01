// A tiny signal shared by useSignOut (writer) and RequireAuth (reader). It lives in its own
// module so those two do not import each other (RequireAuth -> AppShell -> useSignOut).
//
// Clearing the session makes the route guard re-render before any navigation the sign-out
// button asks for can land, so the guard has to know the sign-out was deliberate. A short
// time window (not a consumed flag) is safe under React StrictMode's double render and goes
// stale after a couple of seconds, so a later signed-out visit to a protected URL still
// goes to /login.
let deliberateSignOutAt = 0;

export function noteDeliberateSignOut() {
  deliberateSignOutAt = Date.now();
}

export function justSignedOut() {
  return Date.now() - deliberateSignOutAt < 2000;
}
