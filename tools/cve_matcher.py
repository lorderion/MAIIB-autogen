# import json
# from pathlib import Path
# from api.schemas import CVEItem, NmapService, VulnReport

# DB_PATH = Path(__file__).parent.parent / "data" / "cve_db.json"

# def load_cve_db():
#     with open(DB_PATH) as f:
#         return json.load(f)

# def match_cves(services: list[NmapService]) -> list[CVEItem]:
#     db = load_cve_db()
#     matches = []
#     for svc in services:
#         for cve in db:
#             if cve["service_keyword"] in (svc.service or "") and \
#                (not cve.get("version_keyword") or cve["version_keyword"] in (svc.version or "")):
#                 matches.append(CVEItem(
#                     cve_id=cve["cve_id"],
#                     description=cve["description"],
#                     severity=cve.get("severity", "Medium"),
#                     recommendation=cve["recommendation"]
#                 ))
#     return matches


import json
from pathlib import Path
from typing import List, Any, Dict
from api.schemas import CVEItem, NmapService

DB_PATH = Path(__file__).parent.parent / "data" / "cve_db.json"

def load_cve_db() -> List[Dict[str, Any]]:
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("CVE DB должен быть списком записей")
            return data
    except FileNotFoundError:
        raise RuntimeError(f"CVE database not found at {DB_PATH}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in CVE DB: {e}")

def match_cves(services_input: str) -> str:
    try:
        services_data = json.loads(services_input)
        services = [NmapService(**s) for s in services_data]
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        return json.dumps({
            "error": "Invalid services input",
            "details": str(e)
        })

    db = load_cve_db()
    matches = []

    for svc in services:
        service_name = (svc.service or "").lower()
        version_str = (svc.version or "").lower()

        for cve in db:
            cve_service = cve["service_keyword"].lower()
            cve_version = cve.get("version_keyword", "").lower()

            if cve_service not in service_name:
                continue
            if cve_version and cve_version not in version_str:
                continue

            matches.append(CVEItem(
                cve_id=cve["cve_id"],
                description=cve["description"],
                severity=cve.get("severity", "Medium"),
                recommendation=cve["recommendation"]
            ))

    return json.dumps([c.model_dump() for c in matches])
