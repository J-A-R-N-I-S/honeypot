# Registry plan

**Now:** GitHub Container Registry — `ghcr.io/j-a-r-n-i-s/honeypot:latest`  
Org: https://github.com/J-A-R-N-I-S (0 public repos). Public GHCR is free.

**Later:** optional Docker Hub org `jarnis` (`docker pull jarnis/honeypot:latest`) if we want the shorter name. Not required for customers.

## First publish (needs your GitHub login)

1. Use the existing GitHub user **Jarnis** (public, 0 repos) or another account you prefer.
2. Approve the device-login code I print in chat.
3. I create public repo `honeypot`, push, Actions builds the image.
4. One-time in the GitHub UI: Package → Package settings → Change visibility → **Public**  
   (GHCR packages start private; anonymous `docker pull` only works after this click.)

Customers then:

    docker pull ghcr.io/jarnis/honeypot:latest
