# Polywatch

Flags unusual long-shot bets on Polymarket's news-sensitive markets (fresh wallets, little trading
history, size, low prices, accumulation) using only Polymarket's public read-only APIs.
A flag is a pattern worth a closer look, not proof of wrongdoing.

- `polywatch.py run` — daily job: scan last 25h, merge into `history.json`, record resolutions, build `site/data.js`
- `polywatch.py case <wallet> --condition 0x…` — forensic profile of one wallet
- `polywatch.py scan|watch` — ad-hoc scans
- `site/` — static dashboard (`index.html` + generated `data.js`), deployed to GitHub Pages

Runs daily via `.github/workflows/daily.yml`. Python 3.9+, standard library only.
