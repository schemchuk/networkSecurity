# AI CyberSec Lab — локальні AI-агенти для пентест-аналізу

Локальна (офлайн, без хмарних API) multi-agent система, яка перетворює сирий вивід
пентест-інструментів на **пріоритезований звіт**: сервіси → реальні CVE → severity/priority →
mitigation (як закрити) → detection (що бачить захисник).

Навчально-розробницький проект: власна ізольована lab-практика етичного пентесту +
система локальних агентів, що аналізують реальні знахідки. Працює на локальній LLM
через Ollama.

> ⚠️ Лабораторне та освітнє використання. Межі — у [docs/SCOPE.md](docs/SCOPE.md):
> тільки власна ізольована мережа, тільки аналіз/detection/mitigation, без бойових експлойтів.

---

## Що робить

```
nmap.xml ─▶ parser ─▶ ReconAgent ─▶ VulnAnalysisAgent ─▶ HardeningAgent ─▶ report.md
            (детерм.)   (LLM)         (детерм.: CVE+пріор.)  (LLM: blue-team)
                         └──── усі пишуть findings.json + append-only events.jsonl ────┘
```

- **Recon** — LLM-резюме attack surface + напрямки аналізу для кожного сервісу.
- **Vuln Analysis** — реальні CVE з локального exploitdb (`searchsploit`), severity, пріоритет.
- **Hardening/Detection** — blue-team поради; LLM викликається **лише для пріоритезованих**
  findings (економія інференсу).
- **Report** — Markdown-звіт, findings відсортовані за пріоритетом.

Приклад фрагмента звіту:

```markdown
| ID | Priority | Host | Port | Service | Product | Version | Severity |
|---|---|---|---|---|---|---|---|
| F-0002 | 1 | 10.10.10.5 | 445 | microsoft-ds | Samba smbd | 3.0.20 | high |

### F-0002 — 10.10.10.5:445/tcp microsoft-ds
**CVEs:** CVE-2007-2447
**Mitigation:** Upgrade Samba to a supported release; restrict share access.
**Detection:** Watch smbd logs for anonymous auth; IDS rule for CVE-2007-2447.
```

---

## Інженерні рішення (чому саме так)

- **Детерміноване окремо від LLM.** Точні операції (парсинг nmap, витяг CVE) — звичайний
  Python; LLM лише збагачує текст. Наслідок: **CVE беруться з реального exploitdb, модель їх
  не вигадує.**
- **Hardware-aware вибір моделі.** A/B-бенчмарк на реальному скані показав, що на слабкому
  залізі 7B провалює 65% викликів через timeout, а `qwen2.5:3b` дає 91% completion і вдвічі
  швидше — зміною одного рядка конфігу. Деталі: [docs/benchmarks/model-selection-recon.md](docs/benchmarks/model-selection-recon.md).
- **Стійкість до слабкого/повільного LLM.** Кожен агент толерує помилку інференсу
  (пише `error`-подію й продовжує) — один timeout не валить весь прогін.
- **Vuln-агент повністю детермінований** — швидкий і стабільний незалежно від заліза.
- **Append-only events.jsonl** як спільна шина/аудит усіх агентів.

Архітектура повністю: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Пояснення з нуля (для новачка, з картою «де що лежить»): [docs/how-it-works.md](docs/how-it-works.md).

---

## Стек

Python · Ollama (`qwen2.5:3b`) · Pydantic · python-libnmap · searchsploit (exploitdb) ·
pytest. Усе локально, офлайн.

---

## Запуск

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 1) сканування цілі в ізольованій lab-мережі
nmap -sV -oX /tmp/scan.xml <IP_цілі_в_лабі>

# 2) запуск конвеєра (потрібен запущений `ollama serve`)
python scripts/run.py --nmap /tmp/scan.xml --scenario recon-lab --targets <IP>
# → друкує шлях до runs/<run_id>/report.md
```

Опційно: `scripts/labshell <scenario>` — залогована сесія (кожна команда → `commands.jsonl`,
+ asciinema-каст) для відтворюваності.

Тести: `pytest -q` (38, повністю офлайн — LLM і searchsploit мокаються).

---

## Статус

| Етап | Стан |
|---|---|
| M0 — фундамент (схеми, конфіг, LLM-клієнт, labshell) | ✅ |
| M1 — MVP recon (parser → агент → звіт) | ✅ |
| M2 — vuln-аналіз (реальні CVE, severity, пріоритет) | ✅ |
| M3 — hardening/detection advisor | ✅ |
| M5 — портфоліо-поліш (README, sample, бенчмарк) | ✅ |
| M2.4 RAG · M4 оркестрація | ⏸️ відкладено до апгрейду заліза |

Перевірено на реальному прогоні проти Metasploitable2 (живі CVE: vsftpd, UnrealIRCd,
telnet, VNC тощо).
