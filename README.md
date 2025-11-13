# custom-nakama

Custom Nakama game server with multi-database support and PgBouncer connection pooling.

## Prerequisites

- Docker or Podman
- Go 1.25+ (for local development)

## Architecture

- **PostgreSQL**: Primary database (port 5432)
- **PgBouncer**: Connection pooler (port 6432)
- **Nakama**: Game server (ports 7349, 7350)

## Quick Start

### 1. Start Services with Docker Compose

```bash
docker compose up -d
```

This will start:
- PostgreSQL database
- PgBouncer connection pooler
- Custom Nakama server

### 2. Run Database Migrations

Run migrations for all configured databases (region_a, region_b):

```bash
# run locally
go run main.go migrate up
```