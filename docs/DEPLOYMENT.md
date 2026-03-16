# CyberGuard — Deployment Guide
## Ubuntu VPS (22.04 LTS)

---

## 📋 Prerequisites

- Ubuntu 22.04 LTS VPS (minimum 2 CPU / 4GB RAM recommended)
- Domain name pointed to your server's IP
- Root or sudo access

---

## 1. Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose v2
sudo apt install docker-compose-plugin -y

# Install Certbot for SSL
sudo apt install certbot -y

# Install useful tools
sudo apt install git ufw fail2ban -y
```

---

## 2. Firewall Setup

```bash
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 80/tcp     # HTTP
sudo ufw allow 443/tcp    # HTTPS
sudo ufw enable
sudo ufw status
```

---

## 3. Clone & Configure

```bash
# Clone the project
git clone https://github.com/your-org/cyberguard.git /opt/cyberguard
cd /opt/cyberguard

# Copy environment file
cp .env.example .env

# Edit with your values
nano .env
```

### Required environment variables to set:
```
POSTGRES_PASSWORD=<strong-random-password>
SECRET_KEY=<64-char-random-string>
NEXTAUTH_SECRET=<random-string>
NEXTAUTH_URL=https://yourdomain.com
NEXT_PUBLIC_API_URL=https://yourdomain.com/api/v1
ANTHROPIC_API_KEY=sk-ant-...
SMTP_USER=your@email.com
SMTP_PASSWORD=your-smtp-password
```

Generate random secrets:
```bash
# Generate SECRET_KEY
python3 -c "import secrets; print(secrets.token_hex(32))"

# Generate NEXTAUTH_SECRET
openssl rand -base64 32
```

---

## 4. SSL Certificate (Let's Encrypt)

```bash
# Stop any running web server
sudo systemctl stop nginx 2>/dev/null || true

# Get certificate (replace with your domain)
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Certificates are at:
# /etc/letsencrypt/live/yourdomain.com/fullchain.pem
# /etc/letsencrypt/live/yourdomain.com/privkey.pem

# Create nginx ssl directory and symlink
mkdir -p /opt/cyberguard/nginx/ssl
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem /opt/cyberguard/nginx/ssl/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem /opt/cyberguard/nginx/ssl/
sudo chmod 644 /opt/cyberguard/nginx/ssl/*.pem
```

---

## 5. Update Nginx Config

```bash
# Edit nginx.conf and replace 'your-domain.com' with your actual domain
nano /opt/cyberguard/nginx/nginx.conf
# Change: server_name your-domain.com www.your-domain.com;
```

---

## 6. Deploy

```bash
cd /opt/cyberguard

# Build and start all services
docker compose up -d --build

# Check status
docker compose ps

# View logs
docker compose logs -f
docker compose logs backend -f
docker compose logs frontend -f
```

---

## 7. Database Migration

```bash
# Run Prisma migrations (frontend container)
docker compose exec frontend npx prisma migrate deploy

# Create admin user (optional — use the API or seed script)
docker compose exec backend python -c "
import asyncio
from app.core.database import AsyncSessionLocal
from app.models.models import User, UserRole, Subscription, SubscriptionPlan, SubscriptionStatus
from app.core.security import get_password_hash
import cuid2

async def create_admin():
    async with AsyncSessionLocal() as db:
        user = User(
            id=cuid2.cuid(),
            email='admin@yourdomain.com',
            name='Admin',
            password=get_password_hash('ChangeMe123!'),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(user)
        sub = Subscription(
            id=cuid2.cuid(),
            user_id=user.id,
            plan=SubscriptionPlan.PREMIUM,
            status=SubscriptionStatus.ACTIVE,
            scans_limit=999,
        )
        db.add(sub)
        await db.commit()
        print(f'Admin created: {user.email}')

asyncio.run(create_admin())
"
```

---

## 8. Auto-Renewal for SSL

```bash
# Add cron job for SSL renewal
sudo crontab -e
# Add this line:
0 3 * * * certbot renew --quiet && cp /etc/letsencrypt/live/yourdomain.com/*.pem /opt/cyberguard/nginx/ssl/ && docker exec cyberguard_nginx nginx -s reload
```

---

## 9. Monitoring & Maintenance

```bash
# View all logs
docker compose logs -f

# View specific service
docker compose logs backend -f --tail=100

# Restart a service
docker compose restart backend

# Update application
git pull
docker compose up -d --build

# Database backup
docker compose exec postgres pg_dump -U cyberguard cyberguard > backup_$(date +%Y%m%d).sql

# Restore database
cat backup.sql | docker compose exec -T postgres psql -U cyberguard cyberguard
```

---

## 10. Health Checks

```bash
# API health
curl https://yourdomain.com/health

# Check all containers
docker compose ps

# Resource usage
docker stats
```

---

## Project Structure

```
cyberguard/
├── frontend/                    # Next.js 15 App
│   ├── src/app/                 # App Router pages
│   │   ├── auth/login/          # Login page
│   │   ├── auth/register/       # Registration
│   │   ├── dashboard/           # Client dashboard
│   │   │   ├── page.tsx         # Overview
│   │   │   ├── scans/           # Scan management
│   │   │   ├── reports/         # Report center
│   │   │   ├── targets/         # Asset management
│   │   │   ├── monitoring/      # Monitoring
│   │   │   ├── alerts/          # Alerts
│   │   │   ├── billing/         # Subscription
│   │   │   └── admin/           # Admin panel
│   │   └── api/auth/            # NextAuth handler
│   ├── prisma/schema.prisma     # Database schema
│   └── src/lib/api.ts           # API client
│
├── backend/                     # FastAPI Python App
│   ├── app/
│   │   ├── main.py              # FastAPI entry point
│   │   ├── core/
│   │   │   ├── config.py        # Settings
│   │   │   ├── database.py      # SQLAlchemy async
│   │   │   ├── security.py      # JWT & password
│   │   │   ├── middleware.py    # Security headers
│   │   │   └── celery_app.py    # Task queue
│   │   ├── models/models.py     # SQLAlchemy models
│   │   ├── api/v1/endpoints/    # REST endpoints
│   │   │   ├── auth.py
│   │   │   ├── scans.py
│   │   │   ├── reports.py
│   │   │   ├── targets.py
│   │   │   ├── admin.py
│   │   │   ├── monitoring.py
│   │   │   ├── alerts.py
│   │   │   ├── subscriptions.py
│   │   │   └── notifications.py
│   │   └── services/
│   │       ├── scanner/         # Security scanning engine
│   │       ├── ai/              # AI report generation
│   │       ├── reports/         # PDF generation
│   │       └── monitoring/      # Monitoring tasks
│   └── requirements.txt
│
├── nginx/nginx.conf             # Reverse proxy
├── docker-compose.yml           # Service orchestration
└── .env.example                 # Environment template
```

---

## Architecture

```
Internet → Nginx (443) → Frontend (Next.js :3000)
                       → Backend API (FastAPI :8000)

Backend → PostgreSQL (persisted data)
        → Redis (task queue & cache)
        → Celery Worker (scan execution)
        → Celery Beat (scheduled monitoring)
```

---

## Security Checklist

- [x] HTTPS enforced with Let's Encrypt
- [x] Security headers (HSTS, CSP, X-Frame-Options)
- [x] Rate limiting on API and auth endpoints
- [x] JWT authentication with refresh tokens
- [x] Password hashing with bcrypt
- [x] Role-based access control (Admin/Client)
- [x] Audit logging middleware
- [x] Input validation with Pydantic
- [x] SQL injection protection (SQLAlchemy ORM)
- [x] CORS configuration
- [x] Server token hidden in Nginx
- [x] Non-root container users
- [ ] Enable 2FA (future enhancement)
- [ ] WAF rules (optional: add ModSecurity)

---

## Support

For issues: create a GitHub issue or contact support@cyberguard.io
