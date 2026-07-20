import subprocess
import json
import os

from pathlib import Path

from src.core.schemas import ScanResult, NmapService

def run_nmap(target: str, ports: str = "22,80,443") -> ScanResult:
    """
    Функция для запуска CLI-Nmap, с конечным результатом валидации данных.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    xml_files = os.path.join(os.path.dirname(script_dir), "output.xml")
    xml_file = "output.xml"
    json_file = "output.json"

    try:
        # Шаг 1: запускаем nmap и сохраняем XML
        nmap_cmd = ["nmap", "-p", ports, "-oX", xml_file, target]
        result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError(f"Nmap failed: {result.stderr}")

        # Шаг 2: конвертируем XML в JSON через nmap2json
        convert_cmd = ["python", "-m", "nmap2json", "-i", xml_file]
        convert_result = subprocess.run(convert_cmd, capture_output=True, text=True, timeout=30)
        if convert_result.returncode != 0:
            raise RuntimeError(f"nmap2json failed: {convert_result.stderr}")

        # функционально: запись данных в JSON файл.
        # Path(json_file).write_text(convert_result.stdout)

        nmap_json = json.loads(convert_result.stdout)
        services = []
        for host in nmap_json:
            for port  in host.get("ports", []):
                services.append(NmapService(
                    port=port["portid"],
                    protocol=port["protocol"],
                    service=port.get("service", {}).get("name", "unknown"),
                    version=port.get("service", {}).get("version"),
                    state=port.get("state", {}).get("state")
                ))
    finally:
        if os.path.isfile(xml_files):
            try:
                os.remove(xml_files)
            except Exception as e:
                print(f"Ошибка при удалении {xml_file}: {e}")

    return ScanResult(target=target,  services=services, raw_output=convert_result.stdout)
