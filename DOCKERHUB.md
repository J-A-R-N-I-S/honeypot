# Docker Hub — jarnis/honeypot

Customers pull without an account:

    docker pull jarnis/honeypot:latest

Hermes cannot create the Hub org or push (no Docker daemon here). You do steps 1–3 in the browser, then paste the token here.

## You (once)

1. Open https://hub.docker.com/signup  
   Use a company mailbox (`@jarnis.io`), not a private Gmail if you can.

2. After login: **Organizations → Create Organization**  
   - Name: **`jarnis`** (must be exactly that — Hub said it is still free)  
   - Plan: **Free / Community** is enough (public image)

3. In the org: **Repositories → Create repository**  
   - Name: **`honeypot`**  
   - Visibility: **Public**  
   - Short description: `JARNIS capture-only honeypot (SSH, Telnet, HTTP)`

4. Personal settings → **Security → New Access Token**  
   https://hub.docker.com/settings/security  
   - Description: `hermes-publish`  
   - Access: **Read, Write, Delete**  
   - Copy the token (shown once)

5. Reply in this chat with:

       dockerhub user: <dein-login, nicht die Org>
       dockerhub token: dckr_pat_…
       org: jarnis
       repo: honeypot public

I will store the token only for push, then publish `:latest`.

## After that (I do)

- `docker login` + first `jarnis/honeypot:latest` push (from a builder, or GitHub Actions once the git repo is up)
- App Install tab already says `jarnis/honeypot:latest`
- Every later `main` push rebuilds `:latest` automatically

## Pull test (anyone)

    docker pull jarnis/honeypot:latest
    docker run --rm jarnis/honeypot:latest
    # expected: fatal about missing HONEYPOT_ID / TOKEN — image works
