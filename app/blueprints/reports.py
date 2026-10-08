"""Usage reporting: which packages are used, in which versions, and who pulled them."""
import csv
import io
from collections import defaultdict
from datetime import timedelta

from flask import Blueprint, Response, render_template, request, url_for
from sqlalchemy import func, or_

from ..extensions import db
from ..models import FORMATS, DownloadEvent, Repository, Version, utcnow
from ..sorting import apply_sort
from .ui import audit_required

bp = Blueprint("reports", __name__, url_prefix="/reports")

RANGES = [(7, "7 days"), (30, "30 days"), (90, "90 days"), (365, "1 year"), (0, "all time")]


def _filters():
    a = request.args
    return {
        "days": a.get("days", 30, type=int),
        "repo": a.get("repo", ""),
        "fmt": a.get("fmt", ""),
        "user": a.get("user", ""),
        "q": a.get("q", "").strip(),
    }


def _query(f):
    q = DownloadEvent.query
    if f["days"]:
        q = q.filter(DownloadEvent.created_at >= utcnow() - timedelta(days=f["days"]))
    if f["repo"]:
        q = q.filter(DownloadEvent.repo_name == f["repo"])
    if f["fmt"] in FORMATS:
        q = q.filter(DownloadEvent.format == f["fmt"])
    if f["user"]:
        q = q.filter(DownloadEvent.username == f["user"])
    if f["q"]:
        q = q.filter(DownloadEvent.package_name.contains(f["q"]))
    return q


def _ctx(f):
    return {"f": f, "ranges": RANGES, "formats": FORMATS,
            "repos": [r.name for r in Repository.query.order_by(Repository.name)]}


def _csv(filename, header, rows):
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(header)
    w.writerows(rows)
    return Response("﻿" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


@bp.get("/")
@audit_required
def overview():
    f = _filters()
    base = _query(f)
    ids = base.with_entities(DownloadEvent.id).subquery()
    E = DownloadEvent
    scoped = db.session.query(E).filter(E.id.in_(db.select(ids.c.id)))

    total = scoped.count()
    kpi = {
        "pulls": total,
        "users": scoped.with_entities(func.count(func.distinct(E.username))).scalar() or 0,
        "packages": scoped.with_entities(func.count(func.distinct(E.package_id))).scalar() or 0,
        "versions": scoped.with_entities(func.count(func.distinct(E.version_id))).scalar() or 0,
    }
    proxied = scoped.filter(E.cache_hit.isnot(None))
    proxied_total = proxied.count()
    kpi["cache_rate"] = round(100 * proxied.filter(E.cache_hit.is_(True)).count() / proxied_total) \
        if proxied_total else None

    top_packages = (scoped.with_entities(E.format, E.repo_name, E.package_name, E.package_id,
                                         func.count(E.id), func.count(func.distinct(E.username)),
                                         func.count(func.distinct(E.version_id)), func.max(E.created_at))
                    .group_by(E.format, E.repo_name, E.package_name, E.package_id)
                    .order_by(func.count(E.id).desc()).limit(25).all())
    top_users = (scoped.with_entities(E.username, func.count(E.id), func.count(func.distinct(E.package_id)),
                                      func.max(E.created_at))
                 .group_by(E.username).order_by(func.count(E.id).desc()).limit(25).all())

    day = func.date(E.created_at)
    daily = scoped.with_entities(day, func.count(E.id)).group_by(day).order_by(day).all()
    daily = [(str(d), n) for d, n in daily][-90:]
    peak = max((n for _, n in daily), default=0)

    # vulnerable versions that were actually pulled, and by whom
    vuln_rows = (scoped.join(Version, Version.id == E.version_id)
                 .filter(or_(Version.count_critical > 0, Version.count_high > 0))
                 .with_entities(E.version_id, E.username, func.count(E.id), func.max(E.created_at))
                 .group_by(E.version_id, E.username).all())
    agg = defaultdict(lambda: {"users": [], "pulls": 0, "last": None})
    for vid, user, n, last in vuln_rows:
        a = agg[vid]
        a["users"].append(user)
        a["pulls"] += n
        a["last"] = max(filter(None, [a["last"], last]))
    vuln_versions = [(db.session.get(Version, vid), a) for vid, a in agg.items()]
    vuln_versions = sorted([x for x in vuln_versions if x[0]],
                           key=lambda x: (-x[0].count_critical, -x[0].count_high, -x[1]["pulls"]))[:50]

    return render_template("reports/overview.html", kpi=kpi, top_packages=top_packages, top_users=top_users,
                           daily=daily, peak=peak, vuln_versions=vuln_versions, **_ctx(f))


@bp.get("/downloads")
@audit_required
def downloads():
    f = _filters()
    E = DownloadEvent
    q, sort = apply_sort(_query(f), {"time": E.created_at, "user": E.username, "package": E.package_name,
                                     "version": E.version_name, "repo": E.repo_name, "client": E.user_agent,
                                     "cache": E.cache_hit}, "time", default_dirs={"time": "desc"})
    if request.args.get("export") == "csv":
        rows = [(e.created_at.isoformat(sep=" ", timespec="seconds"), e.username, e.format, e.repo_name,
                 e.package_name, e.version_name, e.filename or "", e.ip, e.user_agent,
                 "" if e.cache_hit is None else ("hit" if e.cache_hit else "miss"))
                for e in q.limit(200000)]
        return _csv("downloads.csv", ["Time (UTC)", "User", "Format", "Repository", "Package", "Version",
                                      "File", "IP", "User agent", "Cache"], rows)
    page = q.paginate(per_page=100, error_out=False)
    return render_template("reports/downloads.html", page=page, sort=sort, **_ctx(f))


def usage_items(f):
    """Inventory of all package versions in use (pulled within the range) with consumers."""
    E = DownloadEvent
    rows = (_query(f).with_entities(E.format, E.repo_name, E.package_name, E.version_name, E.version_id,
                                    E.username, func.count(E.id), func.max(E.created_at))
            .group_by(E.format, E.repo_name, E.package_name, E.version_name, E.version_id, E.username).all())
    inv = {}
    for fmt, repo, pkg, ver, vid, user, n, last in rows:
        key = (fmt, repo, pkg, ver)
        item = inv.setdefault(key, {"vid": vid, "users": {}, "pulls": 0, "last": last})
        item["users"][user] = n
        item["pulls"] += n
        item["last"] = max(item["last"], last)
    versions = {v.id: v for v in Version.query.filter(Version.id.in_([i["vid"] for i in inv.values() if i["vid"]]))}
    items = []
    for (fmt, repo, pkg, ver), i in sorted(inv.items()):
        v = versions.get(i["vid"])
        items.append({"format": fmt, "repo": repo, "package": pkg, "version": ver, "v": v, **i})
    return items


@bp.get("/usage")
@audit_required
def usage():
    f = _filters()
    items = usage_items(f)

    if request.args.get("export") == "csv":
        return _csv("package-usage.csv",
                    ["Format", "Repository", "Package", "Version", "Downloads", "Users", "Last pull",
                     "Critical", "High", "Medium", "Low", "Scan status"],
                    [(i["format"], i["repo"], i["package"], i["version"], i["pulls"],
                      ", ".join(f"{u} ({n})" for u, n in sorted(i["users"].items())),
                      i["last"].isoformat(sep=" ", timespec="seconds"),
                      *((i["v"].count_critical, i["v"].count_high, i["v"].count_medium, i["v"].count_low,
                         i["v"].scan_status) if i["v"] else ("", "", "", "", "deleted")))
                     for i in items])
    return render_template("reports/usage.html", items=items, **_ctx(f))


@bp.get("/users/<username>")
@audit_required
def user_report(username):
    f = _filters()
    f["user"] = username
    E = DownloadEvent
    rows = (_query(f).with_entities(E.format, E.repo_name, E.package_name, E.version_name, E.version_id,
                                    func.count(E.id), func.min(E.created_at), func.max(E.created_at))
            .group_by(E.format, E.repo_name, E.package_name, E.version_name, E.version_id)
            .order_by(func.max(E.created_at).desc()).all())
    versions = {v.id: v for v in Version.query.filter(Version.id.in_([r[4] for r in rows if r[4]]))}
    if request.args.get("export") == "csv":
        return _csv(f"pulls-{username}.csv",
                    ["Format", "Repository", "Package", "Version", "Downloads", "First pull", "Last pull"],
                    [(r[0], r[1], r[2], r[3], r[5], r[6].isoformat(sep=" ", timespec="seconds"),
                      r[7].isoformat(sep=" ", timespec="seconds")) for r in rows])
    return render_template("reports/user.html", username=username, rows=rows, versions=versions, **_ctx(f))


# registered as a Jinja global (not a context processor) so imported macros like `pager` can use it
@bp.app_template_global()
def report_url(**overrides):
    args = {**request.args.to_dict(), **overrides}
    return url_for(request.endpoint, **(request.view_args or {}), **{k: v for k, v in args.items() if v != ""})
