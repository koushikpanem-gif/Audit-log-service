"""Runs in a separate OS process: appends over HTTP and prints the assigned seqs."""

from __future__ import annotations

import json
import sys

import httpx2 as httpx


def main() -> None:
    base_url, label, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
    seqs = []
    with httpx.Client(base_url=base_url, timeout=120) as client:
        for index in range(count):
            response = client.post(
                "/audit/events",
                json={
                    "eventType": "LOAD",
                    "actorId": label,
                    "resourceType": "DOCUMENT",
                    "resourceId": f"{label}-{index}",
                    "payload": {"index": index},
                },
                headers={"X-API-Key": "dev-writer-only"},
            )
            if response.status_code != 201:
                print(
                    json.dumps({"error": response.status_code, "body": response.text})
                )
                sys.exit(1)
            seqs.append(response.json()["seq"])
    print(json.dumps(seqs))


if __name__ == "__main__":
    main()
