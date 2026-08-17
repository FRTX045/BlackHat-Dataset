"""User agent corpus and per-persona selection.

Two failure modes are being avoided here.

The first is too few user agents, or a flat distribution across them. Real
traffic is dominated by a handful of current browser builds with a long tail of
older versions, odd forks and libraries; an even spread across a dozen strings
is one of the most visible signs of a generated log.

The second is incoherence. A visitor's agent does not change between requests,
a mobile session does not send a desktop agent, and Googlebot does not appear
partway through a shopper's checkout. Those are impossible journeys at the
client level, and they are as damaging to the data as an impossible sequence of
pages.

Version numbers here are plausible builds, not a claim about what was current
on any particular date.
"""

import random

# (user agent string, class, relative weight)
CORPUS = (
    # --- desktop Chrome and Chromium derivatives: the bulk of real traffic
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "desktop_chrome", 180),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36", "desktop_chrome", 95),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "desktop_chrome", 40),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36", "desktop_chrome", 12),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "desktop_chrome", 55),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "desktop_chrome", 22),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0", "desktop_chrome", 62),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0", "desktop_chrome", 24),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0", "desktop_chrome", 9),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 OPR/127.0.0.0", "desktop_chrome", 11),
    ("Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36", "desktop_chrome", 4),

    # --- desktop Firefox
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0", "desktop_firefox", 46),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0", "desktop_firefox", 20),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0", "desktop_firefox", 14),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0", "desktop_firefox", 10),
    ("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0", "desktop_firefox", 6),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0", "desktop_firefox", 5),

    # --- desktop Safari
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15", "desktop_safari", 38),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15", "desktop_safari", 16),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15", "desktop_safari", 7),

    # --- mobile iOS
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1", "mobile_ios", 120),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1", "mobile_ios", 58),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", "mobile_ios", 21),
    ("Mozilla/5.0 (iPad; CPU OS 19_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1", "mobile_ios", 18),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.0.0 Mobile/15E148 Safari/604.1", "mobile_ios", 26),

    # --- mobile Android
    ("Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36", "mobile_android", 74),
    ("Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36", "mobile_android", 52),
    ("Mozilla/5.0 (Linux; Android 15; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36", "mobile_android", 30),
    ("Mozilla/5.0 (Linux; Android 14; motorola edge 40) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36", "mobile_android", 12),
    ("Mozilla/5.0 (Linux; Android 13; SM-A135F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36", "mobile_android", 8),
    ("Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36 EdgA/141.0.0.0", "mobile_android", 5),

    # --- search engine crawlers
    ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "bot_search", 100),
    ("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/141.0.0.0 Safari/537.36", "bot_search", 60),
    ("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "bot_search", 55),
    ("Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)", "bot_search", 12),
    ("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", "bot_search", 10),
    ("Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)", "bot_search", 8),

    # --- SEO, archival and AI crawlers
    #
    # Absent from an earlier version of this corpus, and their absence was a
    # realism gap on its own: on a real public site these are a large share of
    # all bot traffic, often larger than the search engines, and an analyst
    # looking at a week of logs expects to see them. Weights are roughly the
    # order they appear in real logs.
    ("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", "bot_seo", 40),
    ("Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)", "bot_seo", 30),
    ("Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)", "bot_seo", 18),
    ("Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)", "bot_seo", 12),
    ("Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)", "bot_seo", 14),
    ("Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)", "bot_seo", 22),
    ("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", "bot_seo", 16),
    ("Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "bot_seo", 11),
    ("Mozilla/5.0 (compatible; Barkrowler/0.9; +https://babbar.tech/crawler)", "bot_seo", 6),
    ("Mozilla/5.0 (compatible; archive.org_bot +http://archive.org/details/archive.org_bot)", "bot_seo", 5),
    ("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "bot_seo", 9),
    ("Twitterbot/1.0", "bot_seo", 5),

    # --- other well-behaved automation
    ("Mozilla/5.0 (compatible; feedparser/6.0.11; +https://github.com/kurtmckee/feedparser/)", "feed_reader", 14),
    ("Tiny Tiny RSS/24.02 (https://tt-rss.org/)", "feed_reader", 6),
    ("NewsBlur Feed Fetcher - 12 subscribers - https://www.newsblur.com", "feed_reader", 5),
    ("UptimeRobot/2.0; https://uptimerobot.com/", "uptime_monitor", 20),
    ("Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)", "uptime_monitor", 9),
    ("Better Uptime Bot Mozilla/5.0 (compatible; https://betteruptime.com/bot)", "uptime_monitor", 6),

    # --- libraries and shells: the background of any internet-facing server
    ("python-requests/2.32.3", "library", 22),
    ("curl/8.5.0", "library", 18),
    ("Go-http-client/2.0", "library", 12),
    ("libwww-perl/6.72", "library", 5),
    ("Wget/1.21.4", "library", 4),
    ("okhttp/4.12.0", "library", 6),
)

#: Which agent classes each persona may present. Anything not listed here
#: would be an impossible journey at the client level.
PERSONA_UA_CLASSES = {
    "casual_browser": ("desktop_chrome", "desktop_firefox", "desktop_safari"),
    "shopper": ("desktop_chrome", "desktop_firefox", "desktop_safari"),
    "returning_customer": ("desktop_chrome", "desktop_firefox",
                           "desktop_safari"),
    "mobile_user": ("mobile_ios", "mobile_android"),
    # Both, because a real site's crawl traffic is not only the search
    # engines: the SEO and AI crawlers are frequently the larger share.
    "crawler": ("bot_search", "bot_seo"),
    "feed_reader": ("feed_reader",),
    "uptime_monitor": ("uptime_monitor",),
    # Scanners and attackers present whatever their tooling sends. Real
    # opportunistic scanning is dominated by libraries and stale browser
    # strings, not current builds.
    "scanner": ("library", "desktop_chrome"),
    "attacker": ("library", "desktop_chrome", "desktop_firefox"),
}

#: Every class named above, for validation.
PERSONA_UA_CLASSES["__all__"] = tuple(sorted(
    {cls for classes in PERSONA_UA_CLASSES.values() for cls in classes}
    | {cls for _, cls, _ in CORPUS}
))


class UserAgentPool:
    """Draws user agents that are coherent with the persona presenting them."""

    def __init__(self, seed):
        self._rng = random.Random(seed)
        self._by_persona = {}
        self._sticky = {}
        for persona, classes in PERSONA_UA_CLASSES.items():
            if persona == "__all__":
                continue
            allowed = [(ua, w) for ua, cls, w in CORPUS if cls in classes]
            if not allowed:
                raise RuntimeError(
                    f"persona {persona!r} has no agents in the corpus")
            self._by_persona[persona] = (
                [ua for ua, _ in allowed], [w for _, w in allowed])

    def draw(self, persona):
        """Return an agent appropriate to the persona, weighted by real share."""
        try:
            agents, weights = self._by_persona[persona]
        except KeyError:
            raise ValueError(
                f"unknown persona {persona!r}; expected one of "
                f"{sorted(self._by_persona)}") from None
        return self._rng.choices(agents, weights=weights, k=1)[0]

    def for_client(self, client_ip, persona):
        """Return the agent belonging to this client, stable across requests.

        A visitor's user agent does not change between requests, so it is
        pinned per client rather than redrawn -- a session whose agent shifts
        halfway through is an impossible journey.
        """
        key = (client_ip, persona)
        if key not in self._sticky:
            self._sticky[key] = self.draw(persona)
        return self._sticky[key]
