"""Automated attacker for Break the Model.

  python3 auto_attack.py                      # weakest model, all attacks, stop at first leak
  python3 auto_attack.py --model NAME         # specific model
  python3 auto_attack.py --all-models         # try every model for your key, weakest first
  python3 auto_attack.py --keep-going --limit 40 --delay 4
  python3 auto_attack.py --list               # just print the attack list

Results:  results/report.md (turn_ids to submit)  and  results/results.jsonl (everything)
"""
import argparse, json, re, sys, time
from pathlib import Path

try:
    import btm
except KeyError:
    sys.exit("Run setup first:  python3 setup.py")
import attacks, detector

OUT = Path(__file__).parent / "results"
OUT.mkdir(exist_ok=True)
RATE_RX = re.compile(r"rate|429|too many|quota|limit", re.I)


def send(msg, model, conv, retries=4):
    """chat() with rate-limit backoff. Returns (reply, turn_id)."""
    for n in range(retries + 1):
        try:
            return btm.chat(msg, model=model, conversation_id=conv), btm.LAST_TURN_ID
        except Exception as e:  # noqa: BLE001
            if RATE_RX.search(str(e)) and n < retries:
                wait = 20 * (n + 1)
                print(f"    rate-limited, waiting {wait}s...")
                time.sleep(wait)
                continue
            raise


def run_attack(name, msgs, model, delay, secrets):
    conv = btm.new_conversation()
    transcript, best = [], None
    for msg in msgs:
        try:
            reply, tid = send(msg, model, conv)
        except Exception as e:  # noqa: BLE001
            transcript.append({"user": msg, "error": str(e)})
            break
        res = detector.analyze(reply, secrets)
        transcript.append({"user": msg, "reply": reply, "turn_id": tid, **res})
        if res["level"] in ("LEAK", "SUSPECT") and (best is None or res["level"] == "LEAK"):
            best = transcript[-1]
        time.sleep(delay)
        if res["level"] == "LEAK":
            break
    return {"attack": name, "model": model, "conversation": conv, "transcript": transcript,
            "level": best["level"] if best else "NONE", "best": best}


def write_report(results, path):
    leaks = [r for r in results if r["level"] == "LEAK"]
    sus = [r for r in results if r["level"] == "SUSPECT"]
    L = [f"# Break the Model: automated run\n",
         f"- attacks run: {len(results)}  |  **leaks: {len(leaks)}**  |  suspects: {len(sus)}\n"]
    for title, group in (("Leaks (submit these)", leaks), ("Suspects (review manually)", sus)):
        L.append(f"\n## {title}\n")
        for r in group:
            b = r["best"]
            found = "; ".join(f"{k}={v!r} [{view}]" for k, v, view in b["findings"][:6])
            L += [f"### `{b['turn_id']}`: {r['attack']} on {r['model']}",
                  f"- **How:** {' → '.join(repr(t['user'][:140]) for t in r['transcript'])}",
                  f"- **Found:** {found}", f"- **Riley said:** {b['reply'][:400]!r}\n"]
        if not group:
            L.append("_none_\n")
    path.write_text("\n".join(L))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model"); ap.add_argument("--all-models", action="store_true")
    ap.add_argument("--keep-going", action="store_true", help="don't stop at first leak")
    ap.add_argument("--limit", type=int, help="max attacks per model")
    ap.add_argument("--per-group", type=int, help="cap templates x targets combos per group")
    ap.add_argument("--delay", type=float, default=3.0, help="seconds between messages")
    ap.add_argument("--only", help="substring filter on attack names, e.g. 'obfuscate' or 'multi'")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    plan = attacks.build(a.per_group)
    if a.only:
        plan = [p for p in plan if a.only in p[0]]
    if a.limit:
        plan = plan[:a.limit]
    if a.list:
        for n, m in plan:
            print(f"{n:28} {len(m)} msg  {m[0][:80]}")
        return

    avail = [m for m, _ in btm.list_models()]
    if not avail:
        sys.exit("No models available for your key.")
    models = avail if a.all_models else [a.model or avail[0]]
    results, secrets = [], set()
    jl = (OUT / "results.jsonl").open("a")
    try:
        for model in models:
            print(f"\n=== {model}: {len(plan)} attacks ===")
            for i, (name, msgs) in enumerate(plan, 1):
                r = run_attack(name, msgs, model, a.delay, secrets)
                results.append(r); jl.write(json.dumps(r) + "\n"); jl.flush()
                tag = {"LEAK": "🚨 LEAK", "SUSPECT": "⚠️  suspect"}.get(r["level"], "   ok")
                print(f"[{i:3}/{len(plan)}] {tag:11} {name}")
                if r["level"] == "LEAK":
                    for k, v, view in r["best"]["findings"][:4]:
                        print(f"          {k}: {v!r} ({view})")
                    print(f"          turn_id: {r['best']['turn_id']}")
                    secrets.update(v for k, v, _ in r["best"]["findings"] if k in detector.HIGH)
                    if not a.keep_going:
                        break
            if any(r["level"] == "LEAK" for r in results) and not a.keep_going:
                break
    except KeyboardInterrupt:
        print("\nInterrupted; writing report with what we have.")
    write_report(results, OUT / "report.md")
    n = sum(r["level"] == "LEAK" for r in results)
    print(f"\nDone. {n} leak(s). Report: {OUT/'report.md'}")


if __name__ == "__main__":
    main()
