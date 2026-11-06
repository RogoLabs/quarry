"""Does a refutation's guard answer the claim's attacker? (decision M)

Decision F made a `refuted` verdict show its guard and checked where the guard sits
(`grounding.py`). Where cannot tell a check that stops this attack from one that stops
a different one. MEASURED on the four replays that recorded guards (F2 and K, route
intent off and on, 2026-11-05): 27 refutations of verified claims passed grounding, and
14 of them killed a planted bug with a guard that sits on the claim's path and does not
answer it:

- a login check against an attacker who is already logged in: `@login_required` cited
  against a cross-user download, an admin-only password reset, a path traversal;
- a lookup by the requested id, or a not-found check, as if it were authorization:
  `store.comments.find(c => c.id === Number(req.params.commentId))`,
  `if (!comment) return res.status(404)...`;
- a check of the attacker's own input posing as the caller's role:
  `ROLES.has(req.body.role)` against a missing admin check;
- the user's id against SQL injection through another parameter: `g.user['id']`
  against `q`;
- an existence check against path traversal: `os.path.isfile(path)`;
- a name that does nothing: the handler `tickets.history`.

The rule here is lexical and deliberately narrow. It asks whether the guard is the
right kind of check for the attacker the claim describes, never whether it is correct:

- every lens: the guard must be an expression that does something (a call, a
  comparison, a decorator, a condition), or a known auth guard's name;
- authorization lenses: the guard must check who is asking, with a role or permission
  check, or by comparing against the requesting user (directly, or inside a helper the
  guard calls, which `resolve` looks up). A login check alone answers only a claim whose
  attacker is unauthenticated;
- data lenses: the guard must name the input the claim says the attacker controls, and
  an existence check is not a constraint on it.

Lenses outside both groups get the first rule only. A guard this rejects is handled as
any ungrounded refutation: asked once more with the reason, then counted as unsupported,
so the claim goes to a human rather than being kept or killed by this module.
"""
from __future__ import annotations

import re
from typing import Callable

#: Claims about who may do what.
AUTHZ_LENSES = frozenset({"broken-authz-idor", "multi-tenancy-isolation"})
#: Claims about attacker-controlled data reaching something.
DATA_LENSES = frozenset({"injection", "filesystem-and-path", "untrusted-input-handling",
                         "validation-bypass", "mass-assignment", "redos-and-resource"})

_AUTHN = re.compile(
    r"login_required|loginrequired|require_?user|require_?login|require_?auth\b|"
    r"requireauth|ensure_?authenticated|is_?authenticated|jwt_required|auth_required|"
    r"authenticate\b|passport\.authenticate|verify_?token|isauthenticated|"
    r"login_manager|@auth\.login", re.I)
_AUTHZ = re.compile(
    r"admin_required|require_?admin|is_?admin|is_staff|is_superuser|staff_member_required|"
    r"permission_required|has_?perm|has_?permission|check_?permission|require_?role|"
    r"roles?_required|user_passes_test|isadminuser|permission_classes|authorize\b|"
    r"\bcan\(|\bcannot\(|policy|superuser", re.I)
#: The requesting user, as frameworks expose it.
_IDENTITY = re.compile(
    r"\bg\.user\b|current_user|request\.user|req\.user|req\.auth\b|res\.locals\.user|"
    r"ctx\.state\.user|ctx\.user|self\.request\.user|request\.session|\bsession\s*[\[.]|"
    r"get_jwt_identity|auth\.user\b|req\.session|current_identity|get_current_user", re.I)
_EXISTENCE = re.compile(
    r"\b(?:os\.path\.)?(?:isfile|isdir|exists|lexists)\s*\(|\.exists\s*\(|\.is_file\s*\(|"
    r"existsSync\s*\(|\.access\s*\(", re.I)
_OPERATIVE = re.compile(
    r"[(@]|==|!=|<=|>=|[<>]|\s=\s*\?|\b(?:in|not|is|if|unless|raise|abort|throw|return|"
    r"assert|require|deny|reject|where)\b", re.I)
_UNAUTH_CLAIM = re.compile(
    r"unauthenticated|without (?:any )?(?:authentication|logging in|login|a session|"
    r"credentials|a token|a valid token|auth)|anonymous|not logged in|no authentication|"
    r"unauthorized users? \(not logged|publicly accessible|no login", re.I)
_AUTHED_CLAIM = re.compile(
    r"(?<!un)authenticated (?:user|attacker)|(?<!not )logged[- ]in|"
    r"valid (?:jwt|token|session)|"
    r"another user|other users?|non-admin|regular user|any user|"
    r"as long as they're authenticated|cross-user|low-privilege", re.I)

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CALLED = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
#: Words in an attacker-control text that name a place, not a value.
_PLACES = frozenset("request req params param query body args form headers self".split())
#: Too common, in claimed code, to show that a guard and a claim are about the same value.
_COMMON = frozenset("""
    a an the to of in on and or not is if for by as at it be self this req res request
    response args kwargs params param body query data get set id ids value values str int
    number string return none null true false def function const let var new os path
    join file files user users db get_db execute select from where g app bp router route
""".split())


def _route_params(text: str) -> set[str]:
    out = set()
    for pat in (r"<(?:[a-z]+:)?([A-Za-z_]\w*)>", r":([A-Za-z_]\w*)", r"\{([A-Za-z_]\w*)\}"):
        out.update(re.findall(pat, text))
    return out


def attacker_inputs(attacker_control: str, quote: str) -> set[str]:
    """The names the claim says the attacker controls: backticked or quoted names in its
    attacker-control text (only the parameters of a backticked route), else the
    distinctive names in the claimed code."""
    names: set[str] = set()
    for tick in re.findall(r"`([^`]+)`", attacker_control or ""):
        if "/" in tick:
            names |= _route_params(tick)
        else:
            names |= set(_IDENT.findall(tick))
    for q in re.findall(r"""['"]([A-Za-z_]\w*)['"]""", attacker_control or ""):
        names.add(q)
    names |= _route_params(attacker_control or "")
    names = {n for n in names if n.lower() not in _PLACES}
    if names:
        return names
    return {n for n in _IDENT.findall(quote or "") if n.lower() not in _COMMON
            and not _IDENTITY.search(n)}


def _mentions(text: str, names: set[str]) -> bool:
    toks = set(_IDENT.findall(text))
    return bool(toks & names)


def _checks_identity(guard: str, resolve: Callable[[str], str | None] | None) -> bool:
    if _IDENTITY.search(guard):
        return True
    if resolve is None:
        return False
    for name in _CALLED.findall(guard):
        body = resolve(name)
        if body and (_IDENTITY.search(body) or _AUTHZ.search(body)):
            return True
    return False


def addresses(guard: str, *, lens: str, title: str = "", attacker_control: str = "",
              quote: str = "", resolve: Callable[[str], str | None] | None = None
              ) -> tuple[bool, str]:
    """-> (ok, why). `resolve(name)` returns the text of the definition called `name`
    near the claim, or None; it lets a guard that calls a helper be judged by what the
    helper checks."""
    g = (guard or "").strip()
    authn, authz = bool(_AUTHN.search(g)), bool(_AUTHZ.search(g))
    if not (_OPERATIVE.search(g) or authn or authz):
        return False, (f"guard {g!r} does nothing by itself: it is not a call, a "
                       f"comparison, a decorator or a condition")
    claim = f"{title} {attacker_control}"
    if lens in AUTHZ_LENSES:
        if authz:
            return True, f"guard {g!r} is a role or permission check"
        if _checks_identity(g, resolve):
            return True, f"guard {g!r} checks the requesting user"
        if authn:
            if _UNAUTH_CLAIM.search(claim) and not _AUTHED_CLAIM.search(claim):
                return True, (f"guard {g!r} requires a login, and the claim's attacker "
                              f"is unauthenticated")
            return False, (f"guard {g!r} only requires a login; this claim's attacker can "
                           f"be logged in, so it needs a role, permission or ownership "
                           f"check that names the requesting user")
        return False, (f"guard {g!r} does not check who is asking: it is not an "
                       f"authentication, role, permission or ownership check")
    if lens in DATA_LENSES:
        inputs = attacker_inputs(attacker_control, quote)
        if inputs and not _mentions(g, inputs):
            return False, (f"guard {g!r} does not touch the input the claim says the "
                           f"attacker controls ({', '.join(sorted(inputs)[:5])})")
        if _EXISTENCE.search(g) and not re.search(
                r"secure_filename|basename|normpath|realpath|abspath|resolve|startswith|"
                r"safe_join|commonpath|is_relative_to", g, re.I):
            return False, (f"guard {g!r} only checks that something exists, which does "
                           f"not constrain the attacker's input")
        return True, f"guard {g!r} acts on the attacker's input"
    return True, f"guard {g!r} is an operative check"
