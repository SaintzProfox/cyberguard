# 🛡️ CyberGuard — Cybersecurity SaaS Platform

A full-stack cybersecurity monitoring and scanning platform built for small businesses.

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15 (App Router) + TypeScript |
| UI | Tailwind CSS (dark cyber theme) |
| Auth | NextAuth v5 + JWT |
| Backend | FastAPI (Python 3.12) |
| Database | PostgreSQL 16 |
| ORM | SQLAlchemy (async) + Prisma (frontend) |
| Task Queue | Celery + Redis |
| AI Reports | Anthropic Claude API |
| PDF Export | ReportLab |
| Scanning | Nmap, OpenSSL, dnspython, python-whois |
| Deployment | Docker + Docker Compose + Nginx |

---

## Features

### 🔐 Authentication & RBAC
- Register / Login / Logout with JWT
- Role-based access: **Admin** and **Client**
- Secure password hashing (bcrypt)
- Refresh token rotation

### 📊 Dashboards
- **Client**: Risk score, active scans, recent alerts, vulnerability trend chart
- **Admin**: All users, scan queue, revenue summary, trigger manual scans

### 🔍 Security Scan Engine
Supports scanning:
- **Open ports** (Nmap)
- **SSL certificate** validation & expiry
- **HTTP security headers** (HSTS, CSP, X-Frame-Options, etc.)
- **DNS records** (SPF, DMARC, MX)
- **WHOIS / domain expiry**

### 🤖 AI Report Generator
- Uses **Claude Sonnet** to analyze scan findings
- Generates: Executive Summary, Technical Findings, Recommendations
- Severity classification: INFO → CRITICAL
- **PDF export** with professional formatting

### 📡 Monitoring Module
- Daily automated checks via Celery Beat
- SSL expiry alerts (30/14/7 day warnings)
- Server uptime monitoring
- Domain expiry reminders
- Email + Telegram notifications

### 💳 Subscription System
- **Free**: 3 scans/month
- **Monthly** ($49/mo): 30 scans + daily monitoring + AI reports
- **Premium** ($149/mo): Unlimited scans + priority + PDF export
- Payment-ready architecture (Stripe integration ready)

### 📁 Report Center
- Download PDF reports
- View historical scans
- AI-generated executive summaries

---

## Quick Start (Development)

```bash
# Clone
git clone https://github.com/your-org/cyberguard.git
cd cyberguard

# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Start all services
docker compose up -d --build

# Run migrations
docker compose exec frontend npx prisma migrate dev
docker compose exec frontend npx prisma generate

# Access
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/api/docs
```

---

## Production Deployment

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for full Ubuntu VPS deployment guide including:
- SSL certificate setup (Let's Encrypt)
- Nginx reverse proxy configuration
- Firewall rules
- Auto-renewal and maintenance

---

## Project Structure

```
cyberguard/
├── frontend/          # Next.js 15 App
│   ├── src/app/       # Pages (App Router)
│   ├── src/lib/       # API client, auth config
│   └── prisma/        # Database schema
├── backend/           # FastAPI + Celery
│   ├── app/
│   │   ├── api/       # REST endpoints
│   │   ├── core/      # Config, DB, security
│   │   ├── models/    # SQLAlchemy models
│   │   └── services/  # Scanner, AI, PDF, monitoring
│   └── requirements.txt
├── nginx/             # Reverse proxy config
├── docs/              # Deployment guide
├── docker-compose.yml
└── .env.example
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login |
| GET | `/api/v1/auth/me` | Current user |
| GET | `/api/v1/targets/` | List targets |
| POST | `/api/v1/targets/` | Add target |
| GET | `/api/v1/scans/` | List scans |
| POST | `/api/v1/scans/` | Create scan |
| GET | `/api/v1/scans/{id}` | Scan details + findings |
| GET | `/api/v1/reports/` | List reports |
| GET | `/api/v1/reports/{id}/download` | Download PDF |
| GET | `/api/v1/alerts/` | Security alerts |
| GET | `/api/v1/monitoring/` | Monitors |
| GET | `/api/v1/subscriptions/me` | Subscription info |
| GET | `/api/v1/admin/stats` | Admin statistics |
| GET | `/api/v1/admin/users` | All users |
| GET | `/api/v1/admin/scans` | All scans |
| POST | `/api/v1/admin/scans/{id}/trigger` | Trigger scan |

---

## Environment Variables

See `.env.example` for full list. Key variables:

```env
ANTHROPIC_API_KEY=sk-ant-...       # For AI reports
SMTP_USER=...                       # For email alerts
TELEGRAM_BOT_TOKEN=...             # For Telegram alerts
SECRET_KEY=...                     # JWT signing key
NEXTAUTH_SECRET=...                # NextAuth session key
```

---

## License

MIT License — see LICENSE file for details.
