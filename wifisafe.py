#!/usr/bin/env python3
"""wifisafe — "Насколько безопасен этот Wi-Fi?"

Прототип движка проверок для удаленщиков и владельцев кафе.
Только пассивная/безопасная диагностика сети, к которой вы подключены:
ничего не атакует, не сканирует чужие устройства и не трогает соседей.

Платформа прототипа: macOS. На других ОС часть проверок помечается как
недоступная (заготовка под расширение).

Использование:
    python3 wifisafe.py            # человекочитаемый отчёт
    python3 wifisafe.py --json     # машинный вывод (для дашборда/SaaS)
    python3 wifisafe.py --no-network  # без активных проб (captive/TLS/админка)
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass, field, asdict

# Уровни серьёзности по возрастанию веса для итогового вердикта.
OK, INFO, UNKNOWN, WARN, RISK, CRITICAL = "OK", "INFO", "UNKNOWN", "WARN", "RISK", "CRITICAL"
SEVERITY_WEIGHT = {OK: 0, INFO: 0, UNKNOWN: 1, WARN: 2, RISK: 3, CRITICAL: 4}
SEVERITY_ICON = {OK: "🟢", INFO: "ℹ️", UNKNOWN: "⚪", WARN: "🟡", RISK: "🟠", CRITICAL: "🔴"}


@dataclass
class Finding:
    key: str
    title: str
    severity: str
    detail: str
    recommendation: str = ""


@dataclass
class Report:
    network: str = "(неизвестно)"
    platform: str = ""
    vpn_active: bool = False
    findings: list[Finding] = field(default_factory=list)

    def add(self, **kw) -> None:
        self.findings.append(Finding(**kw))

    @property
    def worst(self) -> str:
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_WEIGHT[s], default=OK)


def run(cmd: list[str], timeout: int = 8) -> str:
    """Запуск команды; возвращает stdout или "" при любой ошибке."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


# --------------------------- сбор данных (macOS) ---------------------------

def wifi_device() -> str:
    out = run(["networksetup", "-listallhardwareports"])
    block = re.search(r"(?:Wi-Fi|AirPort).*?Device:\s*(\w+)", out, re.S)
    return block.group(1) if block else "en0"


def airport_info() -> dict:
    """Парс текущей сети из system_profiler SPAirPortDataType."""
    out = run(["system_profiler", "SPAirPortDataType"], timeout=15)
    info: dict[str, str] = {}
    if "Current Network Information" not in out:
        return info
    tail = out.split("Current Network Information", 1)[1]
    tail = tail.split("Other Local Wi-Fi Networks", 1)[0]
    lines = [ln.rstrip() for ln in tail.splitlines() if ln.strip()]
    # SSID — первая строка-заголовок вида "    sosedi.coffe:" без ключа.
    for ln in lines:
        s = ln.strip()
        if s.endswith(":") and ":" not in s[:-1]:
            info["ssid"] = s[:-1]
            break
    for ln in lines:
        m = re.match(r"\s*([\w /]+):\s*(.+)$", ln)
        if m:
            info[m.group(1).strip()] = m.group(2).strip()
    return info


def default_route_iface() -> str:
    out = run(["route", "-n", "get", "default"])
    m = re.search(r"interface:\s*(\w+)", out)
    return m.group(1) if m else ""


def dhcp_option(dev: str, opt: str) -> str:
    return run(["ipconfig", "getoption", dev, opt]).strip()


def arp_peers(dev: str, gateway: str) -> list[str]:
    """IP соседей, реально наблюдаемых в ARP-кэше (пассивно)."""
    out = run(["arp", "-a"])
    peers = []
    for ln in out.splitlines():
        m = re.search(r"\(([\d.]+)\) at ([0-9a-fA-F:]+|\(incomplete\)) on (\w+)", ln)
        if not m:
            continue
        ip, mac, iface = m.groups()
        if iface != dev or "incomplete" in mac:
            continue
        if ip in (gateway,) or ip.endswith(".255") or mac.lower().startswith("ff:ff"):
            continue
        peers.append(ip)
    return sorted(set(peers))


# --------------------------- активные пробы ---------------------------

def captive_portal_present() -> bool | None:
    """Apple-style detection: /hotspot-detect.html должен вернуть 'Success'."""
    import urllib.request
    try:
        req = urllib.request.Request("http://captive.apple.com/hotspot-detect.html",
                                     headers={"User-Agent": "CaptiveNetworkSupport"})
        body = urllib.request.urlopen(req, timeout=6).read().decode("utf-8", "ignore")
        return "Success" not in body
    except Exception:
        return None


def admin_panel_reachable(gateway: str) -> bool | None:
    import urllib.request
    for scheme in ("http", "https"):
        try:
            ctx = ssl._create_unverified_context()
            urllib.request.urlopen(f"{scheme}://{gateway}/", timeout=5, context=ctx)
            return True
        except urllib.error.HTTPError:
            return True  # ответил (401/403/...) — значит достижим
        except Exception:
            continue
    return False


def tls_intercepted() -> bool | None:
    """True, если доверенное TLS-соединение к известному хосту НЕ валидируется."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(("www.cloudflare.com", 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname="www.cloudflare.com"):
                return False  # рукопожатие прошло, цепочка валидна
    except ssl.SSLCertVerificationError:
        return True
    except Exception:
        return None


# --------------------------- логика проверок ---------------------------

def build_report(do_network: bool) -> Report:
    rep = Report(platform=platform.platform())

    if platform.system() != "Darwin":
        rep.add(key="platform", title="Платформа", severity=INFO,
                detail=f"Прототип реализует проверки для macOS. Текущая ОС: {platform.system()}.",
                recommendation="Запустите на macOS-устройстве, подключённом к проверяемому Wi-Fi.")
        return rep

    dev = wifi_device()
    air = airport_info()
    gateway = dhcp_option(dev, "router")
    dns = dhcp_option(dev, "domain_name_server")
    route_iface = default_route_iface()
    rep.vpn_active = route_iface.startswith("utun")
    rep.network = air.get("ssid", "(SSID скрыт — нужен доступ к геолокации)")

    # 1. Шифрование
    sec = air.get("Security", "")
    su = sec.upper()
    if not sec:
        rep.add(key="encryption", title="Шифрование Wi-Fi", severity=UNKNOWN,
                detail="Не удалось определить тип шифрования.",
                recommendation="Проверьте вручную / разрешите Terminal доступ к геолокации.")
    elif "WPA3" in su:
        rep.add(key="encryption", title="Шифрование Wi-Fi", severity=OK,
                detail=f"{sec} — современное шифрование, у каждого клиента свой сессионный ключ.")
    elif "WPA2" in su:
        rep.add(key="encryption", title="Шифрование Wi-Fi", severity=WARN,
                detail=f"{sec}: общий пароль на всех. Защищает от посторонних снаружи, "
                       "но участники сети с этим паролем потенциально могут расшифровать "
                       "трафик друг друга (перехват handshake при общем ключе).",
                recommendation="Перейти на WPA3-SAE (или WPA3/WPA2-mixed) — у каждого свой ключ.")
    elif "WEP" in su or su in ("NONE", "OPEN", ""):
        rep.add(key="encryption", title="Шифрование Wi-Fi", severity=CRITICAL,
                detail=f"{sec or 'Открытая сеть'}: трафик не защищён, любой рядом может его читать.",
                recommendation="Включить минимум WPA2-AES, лучше WPA3. Не работать без VPN.")
    else:
        rep.add(key="encryption", title="Шифрование Wi-Fi", severity=RISK,
                detail=f"{sec}: устаревший/слабый режим.",
                recommendation="Перейти на WPA2-AES/WPA3.")

    # 2. Изоляция клиентов (пассивно по ARP)
    peers = arp_peers(dev, gateway)
    if peers:
        sample = ", ".join(peers[:8]) + (" …" if len(peers) > 8 else "")
        rep.add(key="client_isolation", title="Изоляция клиентов", severity=RISK,
                detail=f"Изоляция, похоже, ВЫКЛЮЧЕНА: в сети видно {len(peers)} соседних "
                       f"устройств ({sample}). Возможны сканирование соседей и MITM через ARP-спуфинг.",
                recommendation="Включить AP/Client Isolation на точке доступа — приоритет №1.")
    else:
        rep.add(key="client_isolation", title="Изоляция клиентов", severity=UNKNOWN,
                detail="Соседних устройств в ARP-кэше не видно. Это не доказывает изоляцию "
                       "(кэш мог быть пуст), но прямых признаков её отсутствия нет.",
                recommendation="Для точной проверки убедиться, что Client Isolation включён в настройках.")

    # 3. Шлюз/роутер
    if gateway:
        rep.add(key="gateway", title="Шлюз / роутер", severity=INFO,
                detail=f"Адрес роутера: {gateway} (интерфейс {dev}).")

    # 4. VPN / Private Relay
    if rep.vpn_active:
        rep.add(key="vpn", title="VPN / Private Relay", severity=OK,
                detail=f"Маршрут по умолчанию идёт через туннель ({route_iface}). "
                       "Ваш трафик зашифрован до VPN-сервера — это защищает вас на этой сети.")

    # 5. DNS
    if dns:
        rep.add(key="dns", title="DNS-резолвер", severity=INFO,
                detail=f"DHCP выдал DNS: {dns}. Явных признаков подмены нет "
                       "(для глубокой проверки нужен тест резолвинга известных доменов).")

    if not do_network:
        rep.add(key="network_probes", title="Активные пробы", severity=INFO,
                detail="Пропущены (--no-network): captive-portal, доступность админки, TLS.")
        return rep

    # 6. Captive portal
    cap = captive_portal_present()
    if cap is True:
        rep.add(key="captive", title="Captive portal", severity=INFO,
                detail="Обнаружен перехват HTTP (страница входа). Убедитесь, что вход идёт по HTTPS.")
    elif cap is False:
        rep.add(key="captive", title="Captive portal", severity=OK,
                detail="Captive-портал не обнаружен, прямой выход в интернет.")

    # 7. TLS / MITM
    tls = tls_intercepted()
    if tls is True:
        rep.add(key="tls", title="Перехват TLS", severity=CRITICAL,
                detail="Доверенное TLS-соединение к известному хосту НЕ прошло проверку сертификата — "
                       "возможен перехват трафика (MITM/SSL-inspection).",
                recommendation="Не вводить пароли, немедленно использовать доверенный VPN.")
    elif tls is False:
        rep.add(key="tls", title="Перехват TLS", severity=OK,
                detail="TLS-сертификат известного хоста валиден — признаков перехвата HTTPS нет.")

    # 8. Админка роутера (информативно — больше для владельца)
    if gateway:
        adm = admin_panel_reachable(gateway)
        if adm is True:
            rep.add(key="admin", title="Админка роутера", severity=WARN,
                    detail=f"Веб-интерфейс {gateway} доступен из этой (гостевой) сети.",
                    recommendation="Закрыть доступ к админке из гостевого сегмента; сменить дефолтный пароль.")
        elif adm is False:
            rep.add(key="admin", title="Админка роутера", severity=OK,
                    detail="Веб-интерфейс роутера из этой сети не отвечает.")

    return rep


# --------------------------- вывод ---------------------------

def verdict(rep: Report) -> tuple[str, str]:
    w = rep.worst
    if w == CRITICAL:
        v = "🔴 НЕБЕЗОПАСНО"
        advice = "Избегайте ввода паролей и работы без VPN."
    elif w in (RISK, WARN):
        v = "🟠 С ОСТОРОЖНОСТЬЮ"
        advice = "Ок для обычного браузинга; для логинов и работы используйте VPN."
    else:
        v = "🟢 ПРИЕМЛЕМО"
        advice = "Грубых проблем не видно. VPN всё равно повышает приватность."
    if rep.vpn_active:
        advice += " Сейчас у вас активен VPN/Private Relay — это снижает риск лично для вас."
    return v, advice


def render_human(rep: Report) -> str:
    v, advice = verdict(rep)
    lines = [
        "",
        "  Насколько безопасен этот Wi-Fi?",
        f"  Сеть: {rep.network}",
        "  " + "-" * 52,
        f"  ВЕРДИКТ: {v}",
        f"  {advice}",
        "  " + "-" * 52,
    ]
    for f in rep.findings:
        lines.append(f"  {SEVERITY_ICON[f.severity]} {f.title}: {f.detail}")
        if f.recommendation:
            lines.append(f"      → {f.recommendation}")
    lines.append("")
    return "\n".join(lines)


def render_json(rep: Report) -> str:
    v, advice = verdict(rep)
    payload = {
        "network": rep.network,
        "platform": rep.platform,
        "vpn_active": rep.vpn_active,
        "verdict": v,
        "advice": advice,
        "worst_severity": rep.worst,
        "findings": [asdict(f) for f in rep.findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Насколько безопасен этот Wi-Fi? (пассивная диагностика)")
    ap.add_argument("--json", action="store_true", help="машинный вывод JSON")
    ap.add_argument("--no-network", action="store_true", help="без активных проб (captive/TLS/админка)")
    args = ap.parse_args(argv)

    rep = build_report(do_network=not args.no_network)
    print(render_json(rep) if args.json else render_human(rep))
    return SEVERITY_WEIGHT[rep.worst]  # ненулевой код = есть на что обратить внимание


if __name__ == "__main__":
    sys.exit(main())
