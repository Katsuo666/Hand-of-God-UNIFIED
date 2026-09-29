# -*- coding: utf-8 -*-
"""Orquestrador OSINT de pessoa: variações de username/email + links de busca."""

import re
from datetime import datetime
from typing import Any, Dict
from urllib.parse import quote

SOCIAL_NETWORKS = [
    ("LinkedIn", "https://www.linkedin.com/search/results/people/?keywords={name}"),
    ("Facebook", "https://www.facebook.com/search/people/?q={name}"),
    ("Twitter", "https://twitter.com/search?q={name}&f=users"),
    ("Instagram", "https://www.instagram.com/{username}/"),
    ("GitHub", "https://github.com/search?q={name}&type=Users"),
    ("YouTube", "https://www.youtube.com/results?search_query={name}"),
    ("Reddit", "https://www.reddit.com/search/?q={name}&type=user"),
    ("TikTok", "https://www.tiktok.com/search/user?q={name}"),
]

EMAIL_DOMAINS = ["gmail.com", "hotmail.com", "yahoo.com.br", "outlook.com"]


class PersonOSSINT:
    def analyze(self, name: str, location: str = None) -> Dict[str, Any]:
        username = re.sub(r"[^a-zA-Z0-9]", "", name).lower()
        parts = name.lower().split()

        result: Dict[str, Any] = {
            "target": name,
            "type": "person",
            "timestamp": datetime.now().isoformat(),
            "username_guess": username,
            "location_hint": location,
            "possible_usernames": [],
            "email_variants": [],
            "social_links": {},
            "search_engines": {},
        }

        if len(parts) >= 2:
            fn, ln = parts[0], parts[-1]
            result["possible_usernames"] = list({
                fn, ln, f"{fn}{ln}", f"{fn}.{ln}", f"{fn}_{ln}",
                f"{fn[0]}{ln}", username, f"{username}123",
            })
            for dom in EMAIL_DOMAINS:
                result["email_variants"] += [
                    f"{fn}@{dom}", f"{fn}.{ln}@{dom}", f"{fn}{ln}@{dom}",
                ]

        for net, url_tmpl in SOCIAL_NETWORKS:
            result["social_links"][net] = url_tmpl.replace(
                "{name}", quote(name)
            ).replace("{username}", username)

        enc_name = quote(f'"{name}"')
        result["search_engines"] = {
            "Google": f"https://www.google.com/search?q={enc_name}",
            "Bing": f"https://www.bing.com/search?q={enc_name}",
            "DuckDuckGo": f"https://duckduckgo.com/?q={enc_name}",
        }
        if location:
            enc_loc = quote(f'"{name}" "{location}"')
            result["search_engines"]["Google+Location"] = f"https://www.google.com/search?q={enc_loc}"

        return result
