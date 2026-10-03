"""python manage.py reset_demo — delete events/analyses/incidents and restore the seed baselines."""
from __future__ import annotations

from django.core.management.base import BaseCommand

from agents.resources import reset_resources
from api.models import AgentRun, Analysis, Event, Incident, Simulation
from core.config import get_config


class Command(BaseCommand):
    help = "Clear all demo data (events, analyses, incidents, simulations) and reset user baselines."

    def add_arguments(self, parser):
        parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    def handle(self, *args, **opts):
        if not opts["yes"] and input("Delete all events, analyses and incidents? [y/N] ").lower() != "y":
            self.stdout.write("Aborted.")
            return
        for model in (Incident, Event, AgentRun, Analysis, Simulation):
            model.objects.all().delete()
        cfg = get_config()
        cfg.path(cfg.ml.behavior.baselines_path).unlink(missing_ok=True)
        cfg.path(cfg.rl.runtime_q_table_path).unlink(missing_ok=True)  # forget analyst-feedback learning
        reset_resources()
        self.stdout.write(self.style.SUCCESS(
            "Demo data cleared; baselines and the Q-table will be re-seeded from models/ on next use."))
