# Traceon backend

## Local setup

From the repository root, install the backend dependencies and apply the database migration:

```powershell
python -m pip install -r backend/requirements.txt
alembic -c backend/alembic.ini upgrade head
uvicorn app.main:app --app-dir backend --reload
```

The API defaults to a SQLite database at `backend/traceon.db`. That local database is ignored by Git. To use PostgreSQL, set `TRACEON_DATABASE_URL` before running Alembic or the API:

```powershell
$env:TRACEON_DATABASE_URL = "postgresql+psycopg://<user>:<password>@localhost:5432/traceon"
```

Keep credentials in your local environment or secret manager. Do not commit them.

## Database migrations

Apply the current schema:

```powershell
alembic -c backend/alembic.ini upgrade head
```

Create a new migration after changing a database model:

```powershell
alembic -c backend/alembic.ini revision --autogenerate -m "describe the schema change"
```

Review generated migrations before applying them. SQLite is intended for local development; PostgreSQL uses the same SQLAlchemy models.

## Health endpoint

```powershell
Invoke-RestMethod http://localhost:8000/v1/health
```

Expected response:

```json
{"status":"ok"}
```
