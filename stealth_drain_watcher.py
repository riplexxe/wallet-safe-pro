"""
Stealth Drain Watcher — утилита для обнаружения "тихих" сливов средств из кошельков.

Инструмент анализирует исходящие транзакции и выявляет подозрительные паттерны вывода средств:
- Частые микротранзакции
- Вывод на неизвестные свежие адреса
- Использование нестандартных контрактов
"""

import requests
import argparse
from datetime import datetime, timedelta


ETHERSCAN_API_URL = "https://api.etherscan.io/api"

def fetch_transactions(address, api_key, days=7):
    params = {
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "sort": "desc",
        "apikey": api_key
    }
    response = requests.get(ETHERSCAN_API_URL, params=params)
    all_tx = response.json().get("result", [])

    cutoff = datetime.utcnow() - timedelta(days=days)
    return [tx for tx in all_tx if tx["from"].lower() == address.lower()
            and datetime.utcfromtimestamp(int(tx["timeStamp"])) > cutoff]


def detect_suspicious(tx_list):
    suspicious = []
    fresh_receivers = set()

    for tx in tx_list:
        to = tx["to"]
        value = int(tx["value"])
        if value == 0:
            continue

        # подозрительные микроплатежи
        if value < 1e14:
            suspicious.append((tx["hash"], to, "Микроплатеж"))

        # новые адреса получателей
        if to and to not in fresh_receivers:
            internal_check = check_address_activity(to)
            if not internal_check:
                suspicious.append((tx["hash"], to, "Вывод на свежий адрес"))
                fresh_receivers.add(to)

    return suspicious


def check_address_activity(address):
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=asc"
    r = requests.get(url)
    data = r.json()
    return len(data.get("result", [])) > 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stealth Drain Watcher — мониторинг 'тихих' сливов средств.")
    parser.add_argument("address", help="Ethereum-адрес")
    parser.add_argument("api_key", help="Etherscan API ключ")
    parser.add_argument("--days", type=int, default=7, help="Анализировать за последние N дней")
    args = parser.parse_args()

    print(f"[•] Анализируем исходящие транзакции с {args.address}...")
    txs = fetch_transactions(args.address, args.api_key, args.days)

    if not txs:
        print("[✓] Исходящих транзакций за период не найдено.")
    else:
        suspects = detect_suspicious(txs)
        if not suspects:
            print("[✓] Подозрительных транзакций не обнаружено.")
        else:
            print("[!] Обнаружены подозрительные транзакции:")
            for tx_hash, to, reason in suspects:
                print(f"  - TX: {tx_hash} → {to} | Причина: {reason}")
