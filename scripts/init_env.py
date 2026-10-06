"""Create local configuration without overwriting existing credentials."""
from pathlib import Path
import secrets

root = Path(__file__).resolve().parents[1]
target = root / ".env"
if target.exists():
    print(".env already exists; keeping your configuration.")
else:
    template = (root / ".env.example").read_text()
    target.write_text(template.replace("DJANGO_SECRET_KEY=", f"DJANGO_SECRET_KEY={secrets.token_urlsafe(64)}", 1))
    target.chmod(0o600)
    print("Created .env with a random Django secret. Add your OAuth credentials to enable login.")

