from collections import defaultdict
import argparse

def parse_args():
    p = argparse.ArgumentParser(description="Login anomaly detector")
    p.add_argument("--dawn", type=int, default=6, help="Dawn threshold hour (default: 6)")
    p.add_argument("--log", type=str, default="log.txt", help="Log file path (default: log.txt)")
    p.add_argument("--ip-threshold", type=int, default=5, help="IP failed-login threshold (default: 5)")
    p.add_argument("--user-threshold", type=int, default=5, help="User total failed-login threshold (default: 5)")
    p.add_argument("--only-attack", action="store_true", help="Print only ATTACK alerts")
    p.add_argument("--top", type=int, default=0, help="Show only top N users in risk ranking (0 = show all)")
    return p.parse_args()

def main():
    args = parse_args()

    '''
    d = {}
    if "user" not in d:
        d["user"] = []
    d["user"].append("ip")
    '''
    logins = defaultdict(list)
    alerts = []
    rankings = []
    attack_users = set()

    with open(args.log, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            user, ip, time, status = line.split(",")
            logins[user].append((ip, time, status))

    for user in logins:
        records = logins[user]  # [(ip, time, status), ...]
        score = 0
        reasons = []

        ips = sorted({ip for ip, _, _ in records})

        # rule 1) 여러 IP 로그인
        if len(ips) > 1:
            alerts.append(f"[ERROR] {user} several IP login: {', '.join(ips)}")
            score += 20
            reasons.append(f"multi-ip({len(ips)})")

        # rule 2) 새벽 로그인
        dawn_times = []
        for ip, t, status in records:
            hour = int(t.split(":")[0])
            if hour < args.dawn:
                dawn_times.append(t)
        if dawn_times:
            dawn_times = ", ".join(sorted(dawn_times))
            alerts.append(f"[ERROR] {user} dawn time logins: {dawn_times}")
            score += 10
            reasons.append("dawn-login")

        # rule 4) 같은 IP에서 실패 여러번 
        fails_by_ip = defaultdict(int)
        total_fails = 0
        for ip, t, status in records:
            if status == "FAILED":
                total_fails += 1
                fails_by_ip[ip] += 1

        ip_attack_found = False
        for ip, cnt in sorted(fails_by_ip.items()):
            if cnt >= args.ip_threshold:
                ip_attack_found = True
                alerts.append(f"[ATTACK] {user} brute force from IP {ip} ({cnt} fails)")
                attack_users.add(user)
                score += 60
                reasons.append(f"ip-bruteforce({ip})")

        # rule 3) 유저 전체 실패횟수는 "IP 공격이 없을 때만" 띄우기
        if (not ip_attack_found) and total_fails >= args.user_threshold:
            alerts.append(f"[ATTACK] {user} possible brute force attack ({total_fails} fails)")
            attack_users.add(user)
            score += 40
            reasons.append("user-bruteforce")
        
        rankings.append((score, user, ", ".join(reasons)))

    # 출력 + 파일 저장
    filtered = []
    for a in alerts:
        if args.only_attack and not a.startswith("[ATTACK]"):
            continue
        filtered.append(a)

    for a in filtered:
        print(a)

    # 랭킹 문자열 만들기
    sorted_rankings = sorted(rankings, reverse=True)
    ranking_lines = []
    ranking_lines.append("=== Risk Ranking ===")
    shown = 0
    for score, user, reasons in sorted_rankings:
        if score == 0:
            continue
        if args.only_attack and user not in attack_users:
            continue
        if args.top > 0 and shown >= args.top:
            break
        ranking_lines.append(f"{user}: {score} pts | {reasons}")
        shown += 1

    # 파일 저장: 경고 + 랭킹
    with open("alerts.txt", "w", encoding="utf-8") as out:
        out.write("\n".join(filtered))
        out.write("\n\n")
        out.write("\n".join(ranking_lines))

    print("\n".join(ranking_lines))



if __name__ == "__main__":
    main()
