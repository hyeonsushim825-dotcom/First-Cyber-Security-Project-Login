# Login Anomaly Detector (Security CLI Project)

A Python CLI tool that analyzes login logs and detects suspicious activity such as brute-force attacks and abnormal login patterns.

## Features

- Detect multiple IP logins per user
- Detect dawn-time login attempts
- Detect brute-force attacks
  - Per IP failed login threshold
  - Per user total failed login threshold
- Risk scoring system
- Ranking of suspicious users
- CLI options for flexible analysis
- Report export to alerts.txt

## Usage

py detect.py
py detect.py --only-attack
py detect.py --top 3
py detect.py --dawn 4


## Log Format

user,ip,time,status
user1,8.8.8.8,09:05,FAILED
user2,61.22.1.5,02:10,SUCCESS


## Why this project

Built to practice:

- Security log analysis
- Attack detection logic
- CLI tool design
- Git/GitHub workflow
