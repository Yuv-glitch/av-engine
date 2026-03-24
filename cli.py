import click
import os
from scanner import load_rules, scan_file, scan_directory, save_report
from quarantine import list_quarantined, restore_file
from monitor import start_monitor


@click.group()
def cli():
    """
    \b
    ╔═══════════════════════════════════╗
    ║        AV-ENGINE  v1.0            ║
    ║   Python + YARA Antivirus Tool    ║
    ╚═══════════════════════════════════╝
    """
    pass


# ── SCAN ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("path")
@click.option("--report", is_flag=True, default=False, help="Save scan results to logs/")
@click.option("--quarantine", "auto_quarantine", is_flag=True, default=False, help="Auto-quarantine infected files")
def scan(path, report, auto_quarantine):
    """Scan a file or directory for malware."""

    if not os.path.exists(path):
        click.echo(f"[-] Path not found: {path}")
        return

    rules = load_rules()

    if os.path.isfile(path):
        results = [scan_file(path, rules)]
        result = results[0]
        if result["status"] == "infected":
            click.echo(f"\n[!!!] INFECTED: {path}")
            for m in result["matches"]:
                click.echo(f"      Rule     : {m['rules']}")
                click.echo(f"      Severity : {m['severity']}")
                click.echo(f"      Desc     : {m['description']}")
            if auto_quarantine:
                from quarantine import quarantine_file
                quarantine_file(path, result)
        else:
            click.echo(f"[+] Clean: {path}")

    elif os.path.isdir(path):
        results = scan_directory(path, rules)
        if auto_quarantine:
            from quarantine import quarantine_file
            for r in results:
                if r["status"] == "infected":
                    quarantine_file(r["file"], r)

    if report:
        save_report(results)


# ── MONITOR ───────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("dirs", nargs=-1)
@click.option("--no-quarantine", is_flag=True, default=False, help="Detect only, do not quarantine")
def monitor(dirs, no_quarantine):
    """Watch directories in real-time for malware."""

    watch_dirs = list(dirs) if dirs else ["/tmp", "/home"]
    auto_quarantine = not no_quarantine

    click.echo(f"[*] Auto-quarantine: {'enabled' if auto_quarantine else 'disabled'}")
    start_monitor(watch_dirs=watch_dirs, auto_quarantine=auto_quarantine)


# ── QUARANTINE ────────────────────────────────────────────────────────────────

@cli.group()
def quarantine():
    """Manage quarantined files."""
    pass


@quarantine.command(name="list")
def quarantine_list():
    """List all quarantined files."""
    list_quarantined()


@quarantine.command(name="restore")
@click.argument("index", type=int)
def quarantine_restore(index):
    """Restore a quarantined file by its index number."""
    restore_file(index)


# ── REPORT ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--last", default=5, help="Show last N scan reports")
def report(last):
    """List recent scan reports from logs/."""
    import json
    from pathlib import Path

    log_files = sorted(Path("logs").glob("scan_*.json"), reverse=True)

    if not log_files:
        click.echo("[-] No reports found in logs/")
        return

    for log_file in log_files[:last]:
        click.echo(f"\n[+] Report: {log_file.name}")
        with open(log_file) as f:
            results = json.load(f)

        total = len(results)
        infected = [r for r in results if r["status"] == "infected"]

        click.echo(f"    Scanned  : {total}")
        click.echo(f"    Infected : {len(infected)}")
        click.echo(f"    Clean    : {total - len(infected)}")

        for r in infected:
            click.echo(f"    [!] {r['file']}")
            for m in r["matches"]:
                click.echo(f"        Rule: {m['rules']} | Severity: {m['severity']}")


if __name__ == "__main__":
    cli()
