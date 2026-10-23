# ScamSach evaluation (offline)

Generated: 2026-10-23 13:25

| Split | N | Accuracy (3-class) | Scam recall (flagged) | Strict scam recall | False-positive rate |
|---|---|---|---|---|---|
| dev | 36 | 100% | 100% | 100% | 0% |
| holdout | 14 | 86% | 100% | 88% | 0% |
| all | 50 | 96% | 100% | 97% | 0% |

## Confusion (label -> prediction)

- **dev**: likely_safe->likely_safe: 11, scam->scam: 24, suspicious->suspicious: 1
- **holdout**: likely_safe->likely_safe: 5, scam->scam: 7, scam->suspicious: 1, suspicious->likely_safe: 1
- **all**: likely_safe->likely_safe: 16, scam->scam: 31, scam->suspicious: 1, suspicious->likely_safe: 1, suspicious->suspicious: 1

## Misses

| ID | Lang | Expected | Got | Score | Message |
|---|---|---|---|---|---|
| H03 | hinglish | scam | suspicious | 40 | Hello ji, ghar baithe kamaye Rs 2000-5000 rozana. Bas YouTube videos like karne hai. Inter |
| H14 | en | suspicious | likely_safe | 22 | Mega Diwali sale! Branded watches at 90% off. Limited stock, order today: https://watchsal |
