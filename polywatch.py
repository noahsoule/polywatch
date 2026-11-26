#!/usr/bin/env python3
"""
polywatch — flag possible informed/insider-style trading on Polymarket.

Reconstructs the signals described in the deucalionn "Jensen Huang / NVIDIA" write-up
(fresh wallet, concentrated history, long-shot buys incl. resting limit orders, size) using only the
public, read-only Polymarket APIs (Gamma + Data API v2). Stdlib only.

Commands
  case   <wallet> [--condition 0x..]   forensic profile of one wallet (optionally one market)
  scan   [--hours 6] ...               one pass over active "sensitive" markets
  watch  [--interval 300] ...          scan in a loop, alerting on new hits only
  run    [--hours N]                   scheduled job: scan since last run + history + resolutions + site data
  build  [--resolve]                   rebuild site/data.js (dashboard) from history

A hit is a pattern worth a human look, not proof of insider trading.
"""
import argparse, gzip, json, os, re, sys, time, urllib.parse, urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

GAMMA = "https://gamma-api.polymarket.com"
DATA = "https://data-api.polymarket.com/v2"
UA = "polywatch/0.1"
HERE = os.path.dirname(os.path.abspath(__file__))
HISTORY = os.path.join(HERE, "history.json")
RUNS = os.path.join(HERE, "runs.json")
SITE_DATA = os.path.join(HERE, "site", "data.js")

CATEGORIES = [  # first match wins; prefix match (no trailing \b) so "elect" hits "election"
    ("Corporate", r"\b(ceo|cfo|board of|nvidia|apple|tesla|openai|anthropic|google|meta\b|microsoft|amazon|acqui|merger|ipo\b|earnings|layoff|jensen|huang|musk|altman|zuckerberg|bezos)"),
    ("Fed & macro", r"\b(fed\b|fomc|interest rate|rate (cut|hike)|bps\b|inflation|cpi\b|gdp\b|recession|tariff)"),
    ("Geopolitics", r"\b(iran|israel|ukrain|russia|china|taiwan|gaza|ceasefire|strike|invade|invasion|military|troops|missile|regime|nato|venezuela|maduro|north korea)"),
    ("Elections & politics", r"\b(elect|president|senate|house\b|governor|prime minister|parliament|primary|nominee|nominat|cabinet|secretary|trump|impeach|pardon|leader of|mayor)"),
    ("Courts & legal", r"\b(court|ruling|verdict|indict|charged|sentenc|lawsuit|trial\b)"),
    ("Science & AI", r"\b(ai\b|agi\b|ai model|millennium|nobel|spacex|nasa)"),
]

def category(text):
    for name, rx in CATEGORIES:
        if re.search(rx, text, re.I):
            return name
    return "Other"

# Markets where a small group can know the outcome before the public: personnel moves,
# corporate actions, government decisions, military action, rulings, award results.
SENSITIVE_RE = re.compile(r"""\b(
  ceo|cfo|chair(man|woman)?|board|resign|step(s)?\ down|fired|ousted|rejoin|rehire|reinstat|
  appoint|nominat|confirm(ed)?|cabinet|secretary|ambassador|pardon|commute|indict|charged|arrest|
  acquire|acquisition|merger|buyout|takeover|ipo|delist|bankrupt|layoff|
  announce|launch|release|unveil|earnings|guidance|split|
  executive\ order|tariff|sanction|ban|veto|sign(s)?\ (the|a)\ bill|
  strike|airstrike|invade|invasion|ceasefire|military|troops|missile|
  fed|fomc|rate\ (cut|hike)|interest\ rate|
  supreme\ court|ruling|verdict|sentenc|
  nobel|oscar|grammy|time\ person\ of\ the\ year|
  say|mention|tweet|post\ on|truth\ social
)\b""", re.I | re.X)
SENSITIVE_TAGS = {"politics", "geopolitics", "business", "tech", "economy", "world",
                  "trump", "elon-musk", "fed", "middle-east", "ukraine", "china", "ai",
                  "companies", "big-tech", "mentions", "awards", "courts"}
EXCLUDE_RE = re.compile(r"\b(bitcoin|btc|eth|solana|price of|up or down|temperature|vs\.?|o/u|spread)\b", re.I)


# ---------------------------------------------------------------- http
def get(url, params=None, tries=5):
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    for i in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json",
                                                   "Accept-Encoding": "gzip"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(float(e.headers.get("Retry-After") or 2 ** i))
                continue
            body = e.read().decode(errors="replace")[:300]
            raise RuntimeError(f"HTTP {e.code} {url}: {body}") from None
        except (urllib.error.URLError, TimeoutError):
            time.sleep(2 ** i)
    raise RuntimeError(f"giving up on {url}")


def paged(path, params, max_pages=50, stop=None):
    """Walk a Data API v2 cursor feed. `stop(row)` -> True ends the walk early."""
    cursor = None
    for _ in range(max_pages):
        d = get(DATA + path, {**params, "cursor": cursor})
        for row in d.get("data") or []:
            if stop and stop(row):
                return
            yield row
        pg = d.get("pagination") or {}
        cursor = pg.get("next_cursor")
        if not pg.get("has_more") or not cursor:
            return


def ts(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------- markets
def sensitive_markets(min_volume, max_events):
    seen, out = set(), []
    offset = 0
    while offset < max_events:
        evs = get(GAMMA + "/events", {"active": "true", "closed": "false", "limit": 100,
                                       "offset": offset, "order": "volume24hr", "ascending": "false"})
        if not evs:
            break
        for ev in evs:
            tags = {(t.get("slug") or "").lower() for t in ev.get("tags") or []}
            for m in ev.get("markets") or []:
                cid, q = m.get("conditionId"), m.get("question") or ""
                if not cid or cid in seen or m.get("closed"):
                    continue
                if float(m.get("volumeNum") or m.get("volume") or 0) < min_volume:
                    continue
                text = f"{ev.get('title','')} {q}"
                if EXCLUDE_RE.search(text):
                    continue
                if not (SENSITIVE_RE.search(text) or tags & SENSITIVE_TAGS):
                    continue
                seen.add(cid)
                out.append({"condition": cid, "question": q, "slug": m.get("slug"),
                            "event": ev.get("slug"), "volume": float(m.get("volumeNum") or 0),
                            "liquidity": float(m.get("liquidityNum") or 0),
                            "category": category(text)})
        offset += 100
    return out


# ---------------------------------------------------------------- wallet profiling
_profile_cache = {}

def wallet_profile(wallet, before_ts):
    """Age and diversification of a wallet, using only history up to `before_ts`."""
    key = (wallet, before_ts // 3600)
    if key in _profile_cache:
        return _profile_cache[key]
    first = get(DATA + "/activity", {"user": wallet, "start": 1, "end": before_ts, "limit": 1,
                                      "sort_by": "TIMESTAMP", "sort_direction": "ASC"}).get("data") or []
    first_ts = first[0]["timestamp"] if first else before_ts
    conds, trades, deposits = set(), 0, 0.0
    for a in paged("/activity", {"user": wallet, "start": 1, "end": before_ts, "limit": 500}, max_pages=6):
        if a.get("type") == "TRADE":
            trades += 1
            conds.add(a.get("condition_id"))
        elif a.get("type") == "DEPOSIT":
            deposits += float(a.get("usdc_size") or 0)
    p = {"first_ts": first_ts, "age_h": (before_ts - first_ts) / 3600, "markets": len(conds),
         "trades": trades, "deposits": deposits}
    _profile_cache[key] = p
    return p


def score(agg, prof, cfg):
    """Return (score, reasons). Thresholds are deliberately simple and tunable."""
    s, why = 0, []
    if prof["age_h"] < 24 * 7:
        s += 3; why.append(f"wallet {prof['age_h']:.0f}h old")
    elif prof["age_h"] < 24 * 30:
        s += 1; why.append(f"wallet {prof['age_h']/24:.0f}d old")
    if prof["markets"] <= 2:
        s += 2; why.append(f"only {prof['markets']} market(s) traded before")
    elif prof["markets"] <= 8:
        s += 1; why.append(f"{prof['markets']} markets traded before")
    if agg["usd"] >= 5 * cfg.min_usd:
        s += 2; why.append(f"${agg['usd']:,.0f} bet")
    elif agg["usd"] >= cfg.min_usd:
        s += 1; why.append(f"${agg['usd']:,.0f} bet")
    if agg["avg_price"] <= 0.10:
        s += 2; why.append(f"long shot @ {agg['avg_price']:.3f}")
    elif agg["avg_price"] <= cfg.max_price:
        s += 1; why.append(f"underdog @ {agg['avg_price']:.3f}")
    if agg["fills"] >= 3:
        s += 1; why.append(f"{agg['fills']} fills (accumulation)")
    if agg.get("liq") and agg["usd"] >= 0.25 * agg["liq"]:
        s += 1; why.append(f"{agg['usd']/agg['liq']:.0%} of listed liquidity")
    return s, why


# ---------------------------------------------------------------- scanning one market
def scan_market(m, since, until, cfg):
    buys = defaultdict(lambda: {"usd": 0.0, "shares": 0.0, "fills": 0, "first": None, "last": None,
                                "outcome": None, "name": None, "txs": []})
    # taker_only=false: informed buyers often rest limit orders (the NVIDIA case was 33/34 maker
    # fills), which the default taker-only feed hides entirely. side=BUY keeps each buyer's own row.
    params = {"condition": m["condition"], "side": "BUY", "limit": 1000, "taker_only": "false",
              "filter_type": "CASH", "filter_amount": cfg.min_fill}
    for t in paged("/trades", params, max_pages=cfg.max_pages, stop=lambda r: r["timestamp"] < since):
        if t["timestamp"] > until or float(t["price"]) > cfg.max_price:
            continue
        k = (t["proxy_wallet"], t.get("outcome"))
        b = buys[k]
        b["usd"] += float(t["size"]) * float(t["price"])
        b["shares"] += float(t["size"])
        b["fills"] += 1
        b["first"] = min(b["first"] or t["timestamp"], t["timestamp"])
        b["last"] = max(b["last"] or 0, t["timestamp"])
        b["outcome"], b["name"] = t.get("outcome"), t.get("name") or t.get("pseudonym")
        b["txs"].append(t.get("transaction_hash"))
    hits = []
    for (wallet, outcome), b in buys.items():
        if b["usd"] < cfg.min_usd:
            continue
        b["avg_price"] = b["usd"] / b["shares"]
        b["liq"] = m.get("liquidity")
        prof = wallet_profile(wallet, b["first"])
        sc, why = score(b, prof, cfg)
        if sc >= cfg.threshold:
            hits.append({"score": sc, "why": why, "wallet": wallet, "name": b["name"], "outcome": outcome,
                         "usd": round(b["usd"], 2), "shares": round(b["shares"], 2),
                         "avg_price": round(b["avg_price"], 4), "fills": b["fills"],
                         "first": b["first"], "last": b["last"], "txs": b["txs"][:10],
                         "profile": prof, "market": m})
    return hits


def print_hit(h):
    m = h["market"]
    print(f"\n[{h['score']}] {m['question']}")
    print(f"    {h['name'] or ''} {h['wallet']}  BUY {h['outcome']}  {h['shares']:,.0f} sh  ${h['usd']:,.0f} @ {h['avg_price']}")
    print(f"    {ts(h['first'])} → {ts(h['last'])}   " + "; ".join(h["why"]))
    print(f"    https://polymarket.com/profile/{h['wallet']}   https://polymarket.com/market/{m['slug']}")


def notify(h):
    if sys.platform == "darwin":
        msg = f"{h['score']}: ${h['usd']:,.0f} {h['outcome']} @ {h['avg_price']} — {h['market']['question'][:80]}"
        os.system("osascript -e " + json.dumps(f'display notification {json.dumps(msg)} with title "polywatch"') + " >/dev/null 2>&1")


# ---------------------------------------------------------------- commands
def cmd_scan(cfg, state=None):
    now = int(time.time())
    until = cfg.until or now
    since = until - int(cfg.hours * 3600)
    if cfg.condition:
        mk = get(GAMMA + "/markets", {"condition_ids": cfg.condition}) or \
             get(GAMMA + "/markets", {"condition_ids": cfg.condition, "closed": "true"})
        mk = mk[0] if mk else {}
        markets = [{"condition": cfg.condition, "question": mk.get("question", cfg.condition),
                    "slug": mk.get("slug"), "liquidity": float(mk.get("liquidityNum") or 0),
                    "category": category(mk.get("question", ""))}]
    else:
        markets = sensitive_markets(cfg.min_volume, cfg.max_events)
    print(f"scanning {len(markets)} market(s), window {ts(since)} → {ts(until)}", file=sys.stderr)
    hits, errors = [], 0
    with ThreadPoolExecutor(max_workers=cfg.workers) as pool:
        futs = {pool.submit(scan_market, m, since, until, cfg): m for m in markets}
        for i, f in enumerate(as_completed(futs), 1):
            try:
                hits += f.result()
            except Exception as e:
                errors += 1
                print(f"  ! {futs[f]['question'][:60]}: {e}", file=sys.stderr)
            if i % 100 == 0:
                print(f"  {i}/{len(markets)}", file=sys.stderr)
    cfg._stats = {"markets": len(markets), "errors": errors, "since": since, "until": until}
    hits.sort(key=lambda h: (-h["score"], -h["usd"]))
    new = []
    for h in hits:
        key = f"{h['wallet']}|{h['market']['condition']}|{h['outcome']}"
        if state is not None:
            if state.get(key, 0) >= h["usd"] * 0.999:
                continue
            state[key] = h["usd"]
        new.append(h)
        print_hit(h)
    if cfg.log and new:
        with open(cfg.log, "a") as f:
            for h in new:
                f.write(json.dumps({**h, "logged_at": now}) + "\n")
    if not new:
        print("no hits", file=sys.stderr)
    return new


def cmd_watch(cfg):
    sp = os.path.join(HERE, "state.json")
    try:
        state = json.load(open(sp))
    except Exception:
        state = {}
    while True:
        try:
            for h in cmd_scan(cfg, state):
                if cfg.notify:
                    notify(h)
            json.dump(state, open(sp, "w"))
        except Exception as e:
            print(f"scan failed: {e}", file=sys.stderr)
        time.sleep(cfg.interval)


def cmd_case(cfg):
    w = cfg.wallet.lower()
    rows = list(paged("/activity", {"user": w, "start": 1, "limit": 1000,
                                    "sort_by": "TIMESTAMP", "sort_direction": "ASC"}, max_pages=20))
    if not rows:
        print("no activity"); return
    name = next((r.get("name") for r in rows if r.get("name")), "")
    print(f"wallet {w}  name={name}  first activity {ts(rows[0]['timestamp'])}  rows={len(rows)}")
    by = defaultdict(lambda: {"buy_usd": 0, "buy_sh": 0, "sell_usd": 0, "redeem": 0, "first": None, "title": ""})
    for r in rows:
        c = by[r.get("condition_id") or r["type"]]
        c["title"] = r.get("title") or r["type"]
        c["first"] = c["first"] or r["timestamp"]
        if r["type"] == "TRADE" and r.get("side") == "BUY":
            c["buy_usd"] += r["usdc_size"]; c["buy_sh"] += r["size"]
        elif r["type"] == "TRADE":
            c["sell_usd"] += r["usdc_size"]
        elif r["type"] == "REDEEM":
            c["redeem"] += r["usdc_size"]
    print(f"\n{'first seen':<17} {'bought $':>10} {'sold $':>9} {'redeemed $':>11} {'net $':>10}  market")
    for k, c in sorted(by.items(), key=lambda kv: kv[1]["first"]):
        net = c["sell_usd"] + c["redeem"] - c["buy_usd"]
        print(f"{ts(c['first'])[:16]:<17} {c['buy_usd']:>10,.0f} {c['sell_usd']:>9,.0f} {c['redeem']:>11,.0f} {net:>10,.0f}  {c['title'][:70]}")
    if cfg.condition:
        cond = cfg.condition.lower()
        print(f"\nfills on {cond[:12]}…")
        for r in rows:
            if (r.get("condition_id") or "").lower() == cond:
                print(f"  {ts(r['timestamp'])}  {r['type']:<7} {r.get('side',''):<4} {r.get('outcome',''):<4} "
                      f"{r['size']:>12,.2f} sh  ${r['usdc_size']:>10,.2f}  @ {r.get('price')}  {r['transaction_hash']}")
        first_buy = next((r for r in rows if (r.get("condition_id") or "").lower() == cond and r.get("side") == "BUY"), None)
        if first_buy:
            p = wallet_profile(w, first_buy["timestamp"])
            print(f"\nat first buy: wallet age {p['age_h']:.1f}h, {p['markets']} markets / {p['trades']} trades before, deposits ${p['deposits']:,.0f}")


# ---------------------------------------------------------------- history / dashboard data
def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


def hkey(h):
    return f"{h['wallet']}|{h['market']['condition']}|{h['outcome']}"


def merge_hits(history, hits, now):
    """Insert new flags, update flags whose position grew. Returns count of new/updated."""
    n = 0
    for h in hits:
        k = hkey(h)
        old = history.get(k)
        if old and old["usd"] >= h["usd"] * 0.999:
            continue
        m = h["market"]
        history[k] = {
            "key": k, "score": h["score"], "why": h["why"], "wallet": h["wallet"], "name": h.get("name") or "",
            "outcome": h["outcome"], "usd": h["usd"], "shares": h["shares"], "avg_price": h["avg_price"],
            "fills": h["fills"], "first_trade": h["first"], "last_trade": h["last"], "txs": h["txs"][:10],
            "age_h": round(h["profile"]["age_h"], 1), "prior_markets": h["profile"]["markets"],
            "condition": m["condition"], "question": m["question"], "slug": m.get("slug"),
            "event": m.get("event"), "category": m.get("category") or category(m["question"]),
            "flagged_at": old["flagged_at"] if old else now, "updated_at": now,
            "resolution": old.get("resolution") if old else None,
        }
        n += 1
    return n


def resolve(history):
    """Check unresolved flags against Gamma; record whether the flagged bet won."""
    pending = [h for h in history.values() if not h.get("resolution") and h.get("slug")]
    slugs = sorted({h["slug"] for h in pending})
    results = {}
    def fetch(slug):
        for closed in (None, "true"):
            r = get(GAMMA + "/markets", {"slug": slug, "closed": closed})
            if r:
                return r[0]
        return None
    with ThreadPoolExecutor(max_workers=6) as pool:
        for slug, mk in zip(slugs, pool.map(fetch, slugs)):
            results[slug] = mk
    n = 0
    for h in pending:
        mk = results.get(h["slug"])
        if not mk or not mk.get("closed"):
            continue
        try:
            outs = json.loads(mk.get("outcomes") or "[]")
            prices = [float(x) for x in json.loads(mk.get("outcomePrices") or "[]")]
        except Exception:
            continue
        if not prices or max(prices) < 0.99:
            continue  # closed but not cleanly settled
        winner = outs[prices.index(max(prices))]
        won = (h["outcome"] or "").lower() == winner.lower()
        payout = h["shares"] if won else 0.0
        h["resolution"] = {"winner": winner, "won": won, "payout": round(payout, 2),
                           "pnl": round(payout - h["usd"], 2), "resolved_at": int(time.time())}
        n += 1
    return n


def build_site(history, runs):
    os.makedirs(os.path.dirname(SITE_DATA), exist_ok=True)
    for h in history.values():
        h["category"] = category(h["question"])
    data = {"generated_at": int(time.time()), "runs": runs[-120:],
            "flags": sorted(history.values(), key=lambda h: -h["first_trade"]),
            "config": {"score_threshold": 6}}
    tmp = SITE_DATA + ".tmp"
    with open(tmp, "w") as f:
        f.write("window.POLYWATCH = " + json.dumps(data, separators=(",", ":")) + ";\n")
    os.replace(tmp, SITE_DATA)


def cmd_run(cfg):
    """Daily job: scan, merge into history, resolve old flags, rebuild dashboard data."""
    t0 = time.time()
    history = load(HISTORY, {})
    runs = load(RUNS, [])
    if not cfg.hours:  # cover the gap since the previous run so a late/skipped run loses nothing
        gap_h = (t0 - runs[-1]["at"]) / 3600 + 1 if runs else 25
        cfg.hours = round(min(48, max(7, gap_h)), 2)
    if not history and os.path.exists(cfg.log):  # one-time import of earlier ad-hoc scans
        with open(cfg.log) as f:
            old = [json.loads(l) for l in f if l.strip()]
        for h in old:
            h["market"].setdefault("category", category(h["market"]["question"]))
        merge_hits(history, old, int(t0))
    hits = cmd_scan(cfg)
    new = merge_hits(history, hits, int(t0))
    resolved = resolve(history)
    st = getattr(cfg, "_stats", {})
    runs.append({"at": int(t0), "duration_s": round(time.time() - t0), "markets": st.get("markets", 0),
                 "errors": st.get("errors", 0), "hits": len(hits), "new": new, "resolved": resolved,
                 "window_h": cfg.hours})
    save(HISTORY, history)
    save(RUNS, runs)
    build_site(history, runs)
    print(f"run done: {len(hits)} hits ({new} new/updated), {resolved} resolved, "
          f"{len(history)} flags total, {time.time()-t0:.0f}s", file=sys.stderr)
    if cfg.notify:
        for h in hits:
            if hkey(h) in history and history[hkey(h)]["updated_at"] == int(t0):
                notify(h)


def cmd_build(cfg):
    history = load(HISTORY, {})
    if cfg.resolve:
        print(f"resolved {resolve(history)}", file=sys.stderr)
        save(HISTORY, history)
    build_site(history, load(RUNS, []))
    print(f"wrote {SITE_DATA} ({len(history)} flags)", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "watch", "run"):
        p = sub.add_parser(name)
        p.add_argument("--hours", type=float, default=None if name == "run" else 6,
                       help="look-back window (default 6; for run: since the previous run + 1h, 7-48h)")
        p.add_argument("--until", type=int, help="window end, epoch seconds (backtests)")
        p.add_argument("--condition", help="scan a single market by condition id")
        p.add_argument("--min-usd", type=float, default=1000, help="min aggregated bet per wallet/outcome")
        p.add_argument("--min-fill", type=float, default=50, help="ignore fills smaller than this ($)")
        p.add_argument("--max-price", type=float, default=0.25, help="only buys at or below this price")
        p.add_argument("--min-volume", type=float, default=10000, help="skip markets below this lifetime volume")
        p.add_argument("--max-events", type=int, default=500, help="how many active events to consider")
        p.add_argument("--max-pages", type=int, default=10, help="trade pages per market (1000/page)")
        p.add_argument("--threshold", type=int, default=6, help="min score to report")
        p.add_argument("--log", default=os.path.join(HERE, "alerts.jsonl"))
        p.add_argument("--workers", type=int, default=6, help="markets scanned in parallel")
        if name == "run":
            p.add_argument("--notify", action="store_true")
        if name == "watch":
            p.add_argument("--interval", type=int, default=300)
            p.add_argument("--notify", action="store_true", help="macOS notification per new hit")
    p = sub.add_parser("build", help="rebuild site/data.js from history")
    p.add_argument("--resolve", action="store_true", help="also check resolutions")
    p = sub.add_parser("case")
    p.add_argument("wallet")
    p.add_argument("--condition")
    cfg = ap.parse_args()
    {"scan": cmd_scan, "watch": cmd_watch, "run": cmd_run, "build": cmd_build, "case": cmd_case}[cfg.cmd](cfg)


if __name__ == "__main__":
    main()
