# Deployment guide — AWS Lightsail + Docker

This document covers a single-instance production deploy on AWS Lightsail (Ubuntu 24.04) using Docker Compose, with Nginx + Let's Encrypt for HTTPS and an external MySQL database.

---

## Architecture

```
Internet ──▶ Lightsail :80/:443
                │
                ▼
           Nginx container ──(http://web:8000)──▶ Gunicorn (Django)
                │                                       │
                │                                       └─▶ Hetzner MySQL (external)
                │                                       └─▶ Kasserver SMTP (external)
                ▼
          Certbot container (renews certs every 12h)
```

Nothing stateful lives inside Docker. The database is external; if the instance dies, you redeploy from git and everything reconnects.

---

## One-time: server setup

### 1. Provision Lightsail instance

- Blueprint: **Ubuntu 24.04 LTS** (OS only, not Bitnami Django)
- Plan: **$12/mo (2 GB RAM, 2 vCPU)**
- Region: closest to your Hetzner DB (Frankfurt `eu-central-1` if EU)
- Attach a **static IP** before doing anything else
- Firewall: open **22, 80, 443**. Restrict 22 to your IP.

### 2. Point DNS at the static IP

In your DNS provider, create an A record:

```
mailbox.example.com    A    <your-static-ip>
```

Wait until `dig mailbox.example.com +short` (or `nslookup`) returns the static IP before requesting an SSL cert. Otherwise Let's Encrypt's HTTP-01 challenge will fail.

### 3. SSH in and install Docker

```bash
ssh -i ~/path/to/lightsail-key.pem ubuntu@<static-ip>

# Update + install Docker engine + compose plugin
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

# Let your user run docker without sudo (log out + back in after)
sudo usermod -aG docker $USER
```

Log out and back in, then verify:

```bash
docker --version
docker compose version
```

### 4. Clone the repo

```bash
git clone <your-repo-url> mailbox-transfer
cd mailbox-transfer
```

If the repo is private, set up an SSH deploy key on the server first, or use HTTPS + a personal access token.

### 5. Create production `.env`

```bash
cp .env.example .env
nano .env
```

Fill in **every** value. Critical ones:

| Variable | Notes |
|---|---|
| `DJANGO_SECRET_KEY` | Generate fresh: `python3 -c "import secrets; print(secrets.token_urlsafe(50))"` |
| `DJANGO_DEBUG` | Must be `0` |
| `DJANGO_ALLOWED_HOSTS` | `mailbox.example.com` (your real domain) |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | `https://mailbox.example.com` (with scheme!) |
| `DB_*` | Your Hetzner MySQL credentials |
| `MAILBOX_FERNET_KEY` | **Same key you used locally** — otherwise existing encrypted passwords in the DB become unreadable |
| `GOOGLE_CLIENT_ID/SECRET` | From Google Cloud Console |
| `EMAIL_*` | Your SMTP credentials |

Lock it down:

```bash
chmod 600 .env
```

### 6. First-time HTTPS bootstrap

```bash
chmod +x docker/init-letsencrypt.sh docker/entrypoint.sh

DOMAIN=mailbox.example.com EMAIL=you@example.com ./docker/init-letsencrypt.sh
```

This script:
1. Substitutes your domain into `docker/nginx/conf.d/app.conf`
2. Creates a self-signed dummy cert (so nginx can boot)
3. Starts nginx
4. Requests a real Let's Encrypt cert via the HTTP-01 challenge
5. Reloads nginx with the real cert

If it fails, re-run with `STAGING=1 DOMAIN=... EMAIL=... ./docker/init-letsencrypt.sh` to use Let's Encrypt's staging server (no rate limits) for debugging.

### 7. Start the full stack

```bash
docker compose up -d
docker compose logs -f web   # watch first boot — should run migrations + collectstatic + start gunicorn
```

Visit `https://mailbox.example.com` — you should see the login page.

### 8. Create a superuser (one-off)

```bash
docker compose exec web python manage.py createsuperuser
```

### 9. Configure the Google OAuth SocialApp row

`settings.py` notes that the Google client lives in the DB. Log in to `/admin/socialaccount/socialapp/` and create the SocialApp row with your client ID and secret, attached to the `example.com` Site.

---

## Day-to-day: deploying updates

```bash
ssh ubuntu@<static-ip>
cd mailbox-transfer
git pull
docker compose up -d --build
```

The entrypoint runs migrations + `collectstatic` on every container start.

Roll back:

```bash
git checkout <previous-commit>
docker compose up -d --build
```

---

## Logs, debugging, restarts

```bash
docker compose logs -f web        # Django/gunicorn
docker compose logs -f nginx      # nginx access/error
docker compose logs -f certbot    # cert renewals

docker compose restart web        # restart just the app
docker compose down && docker compose up -d   # full restart

docker compose exec web python manage.py shell      # Django shell
docker compose exec web python manage.py migrate    # ad-hoc migrate
```

---

## SSL renewal

Handled automatically by the `certbot` container, which checks every 12 hours and renews any cert within 30 days of expiry. Nginx auto-reloads every 6 hours to pick up new certs.

Verify renewal works (dry run):

```bash
docker compose exec certbot certbot renew --dry-run
```

---

## Backups

The app is stateless — all persistent data is in the **Hetzner MySQL DB**. Make sure:

- Hetzner managed DB backups are enabled (check the Hetzner console)
- You have a copy of `.env` somewhere safe (it contains `MAILBOX_FERNET_KEY` — without it, encrypted passwords are unrecoverable)
- Take a Lightsail snapshot of the instance after first successful deploy (so you don't have to redo Docker install)

---

## Security checklist

- [ ] `DJANGO_DEBUG=0` in `.env`
- [ ] Fresh `DJANGO_SECRET_KEY` (not the `django-insecure-...` default)
- [ ] `.env` permissions: `chmod 600 .env`
- [ ] SSH port 22 restricted to your IP in Lightsail firewall
- [ ] Lightsail "Lightsail browser SSH" kept on as fallback
- [ ] Django superuser has 2FA enabled (you have `django-two-factor-auth` installed)
- [ ] Snapshot the instance after deploy succeeds
