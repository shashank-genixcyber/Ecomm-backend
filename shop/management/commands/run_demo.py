from django.conf import settings
from django.core.management import BaseCommand, CommandError, call_command

from demo import audit
from demo.provider import LocalProvider


class Command(BaseCommand):
    help = "Start the loopback-only local credential demo and its HTTPS provider."

    def add_arguments(self, parser):
        parser.add_argument("--port", type=int, default=8002, help="Loopback Django port (default: 8002).")

    def handle(self, *args, **options):
        if not settings.DEMO_ENABLED:
            raise CommandError("Set ECOMM_DEMO_MODE=true and run scripts/init_demo.py first.")
        try:
            audit.emit("application.starting", mode="local_demo")
            call_command("migrate", interactive=False, verbosity=0)
            call_command("seed", verbosity=0)
            with LocalProvider(settings.DEMO_ASSET_DIR, settings.DEMO_PROVIDER_PORT, settings.DEMO_FRONTEND_ORIGIN):
                self.stdout.write(f"Demo backend: http://127.0.0.1:{options['port']}\nShared log: " + str(settings.DEMO_LOG_PATH))
                call_command("runserver", f"127.0.0.1:{options['port']}", use_reloader=False, insecure=True, verbosity=1)
        except (audit.AuditUnavailable, OSError, ValueError):
            raise CommandError("Cannot start the local demo. Check asset files, log permissions and configured ports.") from None
