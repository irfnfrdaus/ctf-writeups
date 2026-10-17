# 3NC0R3

- **Category:** Web
- **Author:** ahrixia
- **Flag:** `nexsec26{th3_0nly_0n3_wh0_c0uld_h4ck_m3_337b5dd163a4c4a1427a2b7178303264742a831b8e8935e98ea5b9c2033aeddf}`
- **Tools I used:** Browser DevTools, `curl`, PowerShell, and DeepSeek for analysis/guidance.

> ENCORE is a late-90s concert "shoebox" that went dark in 2009 and got plugged back in for the nostalgia. Fans pin ticket stubs and a few lines about the night. The founder's shoebox is still locked. He never rotated the passphrase, because the only thing that could break in is the memory itself.
>
> Target: `http://koala.nexsec.my:PORT`

---

## TL;DR

I chained four bugs together to solve this:

1. **IDOR** — memory pages live at `/m/<md5(id)>` where `id` is just a sequential integer. By enumerating the hashes I found **hidden "draft" memories** that were never linked on the wall.
2. **Information disclosure** — one hidden draft, written by the founder, told me about a secret file `private/sweet_memory.txt` served by a naive file loader at `/scan?file=`.
3. **Path Traversal / LFI with a broken filter** — the loader decodes the parameter **twice** and strips `../` once in between, so I used a **double-URL-encoded `....//`** to climb out of the `scans/` directory and read the secret file.
4. **Weak, never-rotated credential** — the secret file is a riddle describing the admin passphrase (a leetspeak string in ticket-stub format). I logged in as the founder and the flag was in his private shoebox.

---

## Recon

The landing page (`/`) is a stylised animated cassette. When I viewed the source I noticed a marquee that basically states the mission:

```
carl's box is locked · the only key is a memory
```

and a link to `/wall` ("skip the intro"). The guestbook at `/wall` has a nav bar:

```
/wall   /shoebox   /u/c0untd0wn_carl   /changelog   /login   /register
```

- `/u/c0untd0wn_carl` is the founder's **private** "shoebox": *"this shoebox is private. the only thing that could ever break in is the memory itself."*
- The footer told me how to tell the real flag from decoys: *"house flags wear `nexsec26{ }`. anything else is graffiti on a barrier."* — there are troll `FLAG{...}` strings on the wall, but the real one is `nexsec26{...}`.

Two things on the wall caught my eye:

- Every ticket "polaroid" links to `/m/<hash>`.
- Some ticket stubs reference a file endpoint: `/scan?file=1999/london.txt`.

And two guestbook notes felt like deliberate hints:

- `jen_admin` (2009): *"The old drafts are not on the wall, and that is on purpose."*
- `miss_verity` (2008): *"the only key is a memory."*

---

## Step 1 — IDOR on `/m/<md5(id)>`

I recognised the memory hashes straight away:

| hash | preimage |
|------|----------|
| `c4ca4238a0b923820dcc509a6f75849b` | `md5("1")` |
| `c81e728d9d4c2f636f067f89cc14862c` | `md5("2")` |
| `eccbc87e4b5ce2fe28308fd9f2a7baf3` | `md5("3")` |

So `/m/<hash>` is really `/m/id` with `id = md5(integer)` — a classic **Insecure Direct Object Reference**. I enumerated `md5(0..120)`:

```powershell
$md5 = [System.Security.Cryptography.MD5]::Create()
0..120 | ForEach-Object {
  $h = ([System.BitConverter]::ToString(
          $md5.ComputeHash([Text.Encoding]::ASCII.GetBytes("$_"))
        )).Replace("-","").ToLower()
  $code = (Invoke-WebRequest "http://HOST/m/$h" -UseBasicParsing -SkipHttpErrorCheck).StatusCode
  "$_  $h  $code"
}
```

IDs `1..26` returned `200`. Most were the bands already pinned on the wall, but **five drafts weren't linked anywhere**:

| id | title | author |
|----|-------|--------|
| 6  | note to self | c0untd0wn_carl |
| 13 | login reminder | encore_eddie |
| 17 | Europe | crate_digger |
| 20 | **draft — do not pin** | **c0untd0wn_carl** |
| 25 | wip | tapehead_kai |

> This is exactly what `jen_admin`'s "the old drafts are not on the wall" hint was pointing at.

### Decoys I ignored

Two drafts leak credentials, but I treated them as rabbit holes:

- id 13 — `encore_eddie`: *"My encore login is still `shoebox123`."* (not the founder's account)
- id 6 — `c0untd0wn_carl`: *"Hotmail password is `ilovethe80s`. … The site one is the memory. This is **not** the memory."* (the note disclaims it itself)

---

## Step 2 — The founder's draft points me to an LFI

Draft **id 20** ("draft — do not pin", by `c0untd0wn_carl`) was the pivot I needed:

> *"I wrote the longhand page so I would remember why the passphrase stays the passphrase. It is named `sweet_memory.txt` and it lives in `private/`, one folder beside `scans/`. The loader still serves the scans at `/scan?file=` and I never taught it manners. The copy sitting inside `scans/private/` is a placeholder…"*

From that I understood:

- The file loader `/scan?file=` serves from `scans/` with **no path sanitisation** ("never taught it manners").
- The real secret is `private/sweet_memory.txt`, where `private/` is a **sibling** of `scans/`.
- There's a **decoy** placeholder at `scans/private/sweet_memory.txt`.

I confirmed the layout with a baseline request and the decoy:

```
/scan?file=1999/london.txt           -> real ticket text (loader works)
/scan?file=private/sweet_memory.txt  -> "SCAN COPY — NOT THE LONGHAND … you never actually left /scans"
```

---

## Step 3 — Beating the traversal filter (double-decode + strip)

Naive traversal was blocked:

```
/scan?file=../private/sweet_memory.txt      -> "the loader refused that name"
/scan?file=..%2fprivate/sweet_memory.txt    -> "the loader refused that name"
/scan?file=....//private/sweet_memory.txt   -> "the loader refused that name"
/scan?file=..%252fprivate%252f...           -> returns the DECOY (not refused!)
```

By probing the different responses I reverse-engineered how the loader works:

1. **Decode #1** (framework) runs on the raw query string (`%2e`→`.`, `%2f`→`/`, `%25`→`%`).
2. **Filter** runs on that result and rejects: literal `../`, `..\`, a leading `/`, and **3+ consecutive dots** (`...`).
3. **Decode #2** (the app) runs again — so anything *double*-encoded (`%252f`→`%2f`→`/`) only becomes a real slash now.
4. The app then does a single-pass `replace("../","")` and opens `scans/ + result`.

That explained everything I was seeing: a double-encoded single `../` survives decode #1 (the filter only sees `..%2f`, no literal `/`), becomes `../` at decode #2, and is then **stripped** — leaving `private/...`, which is why I kept landing on the decoy.

**The needle:** I had to deliver `....//` to the strip. `"....//".replace("../","")` collapses to `../` (the strip is non-recursive — it removes the inner `../` and the remnants re-form `../`). But a literal `....` gets caught by the 3-dot rule at decode #1. So I **double-encoded every dot and slash**, so decode #1 only sees inert `%2e`/`%2f` text, and `....//` only materialises at decode #2:

```
raw:      %252e%252e%252e%252e%252f%252fprivate%252fsweet_memory.txt
decode#1: %2e%2e%2e%2e%2f%2fprivate%2fsweet_memory.txt      (no dots/slashes → filter passes)
decode#2: ....//private/sweet_memory.txt
strip:    ../private/sweet_memory.txt
open:     scans/../private/sweet_memory.txt  →  private/sweet_memory.txt   ✓
```

Final request:

```
GET /scan?file=%252e%252e%252e%252e%252f%252fprivate%252fsweet_memory.txt
```

This returned the real `sweet_memory.txt`.

---

## Step 4 — Decoding the passphrase

`sweet_memory.txt` (abridged):

> *febru4ry '86. … front row, stockholm. … a keytar drew the opening line — the one still written across the top of this site — … b3st n1ght of my l1fe. i l0st my voice …*
>
> *people keep asking why i never change the passphrase. … the only one who could ever hack me is that sweet memory. c@n't let it g0.*
>
> *i still type it the way i shouted it. all caps. no spaces. same order as every ticket stub in this shoebox: **who was on stage, where the rink was, the full year**. the letters have been slipping into numbers for twenty years …*
>
> *fat-finger the login all you want. … there is no lockout.*

Here's how I decoded the constraints:

- **Who was on stage** → the subtitle *"the final countdown"* = the band **EUROPE**.
- **Where the rink was** → **STOCKHOLM**.
- **The full year** → **1986**.
- **All caps, no spaces**, **leetspeak** — the note itself shows the map: `a→4`, `e→3`, `i→1`, `o→0`, and **`a→@`** (`c@n't`).
- **"same order as every ticket stub"** — the wall stubs are formatted `BAND @ VENUE`, so I realised the `@` is a **literal separator** (and `c@n't` was the nudge toward it). This was the part that took me longest — my first attempts without the `@` all failed.
- **"there is no lockout"** → I could brute-force the leet variants freely.

Putting it together — `EUROPE` `@` `STOCKHOLM` `1986`, fully leeted:

```
3UR0P3@ST0CKH0LM1986
```

---

## Step 5 — Login and capture the flag

The login is a plain `POST /login` (`username`, `password`, no CSRF, no lockout). I sprayed the leet variants of `EUROPE@STOCKHOLM1986`; a wrong password returns `401` with a "nope" message, and success is a `302` redirect that sets a session cookie.

I ran it from the browser console because the POST was reliable there and the session cookie is kept automatically:

```js
const user="c0untd0wn_carl", w="EUROPE@STOCKHOLM1986";
// generate leet combinations of E->3 and O->0, keep '@' literal, then POST each...
```

The winning credential:

```
username: c0untd0wn_carl
password: 3UR0P3@ST0CKH0LM1986
```

After the `302`, I opened the founder's private shoebox `/u/c0untd0wn_carl` while authenticated and the flag was right there:

```
nexsec26{th3_0nly_0n3_wh0_c0uld_h4ck_m3_337b5dd163a4c4a1427a2b7178303264742a831b8e8935e98ea5b9c2033aeddf}
```

I liked that the flag text — *"the only one who could hack me"* — ties straight back to Carl's note: *"the only one who could ever hack me is that sweet memory."*

---

## Mitigations

- **IDOR:** don't derive object URLs from `md5(sequential_id)`; use unguessable, authorization-checked identifiers, and enforce ownership on draft/private records.
- **Path traversal:** never build file paths from user input with blacklists. Canonicalise with a safe join (e.g. `werkzeug.utils.safe_join`), resolve the real path, and verify it stays inside the intended directory. Decode exactly once and reject anything that isn't an allow-listed relative name.
- **Credentials:** don't ship static, guessable, "never-rotated" passphrases; add rate-limiting and lockout on authentication.

## The exploit chain, at a glance

```
IDOR (/m/md5(id))  →  hidden draft discloses /scan LFI + private/sweet_memory.txt
                   →  double-encoded ....// bypasses the decode/strip filter
                   →  leetspeak passphrase (EUROPE @ STOCKHOLM 1986)
                   →  login as c0untd0wn_carl  →  flag
```
