# SSH Log Analysis & Threat Detection Tool

A Python tool that parses Linux SSH authentication logs (`auth.log`) and flags IP addresses with suspicious numbers of failed login attempts. It is the foundation for a small SOC-style detection tool, built step by step.

> **Status: work in progress.** The core parsing and threshold detection work, but several planned detections are not implemented yet and there are known bugs. See [Known Issues](#known-issues) and [Roadmap](#roadmap).

## What it does (currently)

- Reads an SSH `auth.log` file line by line
- Picks out `Failed password` events
- Extracts the **timestamp**, **source IP** and **targeted username** from each event (handles both `for root` and `for invalid user test` formats)
- Groups failed attempts by IP address
- Prints a summary report of the total failed attempts and any IP at or above a configurable threshold (default: 5)

## Requirements

- Python 3.9+ (developed on Python 3.15)
- No third-party libraries (standard library only)

## Usage

1. Put your log file in the same folder as the script and name it `auth.log`.
2. Run:

```
py detector.py
```

(Replace `detector.py` with your script's filename. On macOS/Linux use `python3 detector.py`.)

## Expected input format

Standard syslog-style SSH lines, for example:

```
Oct 22 10:15:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52144 ssh2
Oct 22 10:15:07 server sshd[1234]: Failed password for invalid user test from 203.0.113.5 port 52158 ssh2
```

The parser relies on this layout: the timestamp is the first three fields, the username follows the word `for`, and the IP is the fourth field from the end of the line.

## Example output

Using the included sample log:

```
REPORT OF FAILED LOGIN ATTEMPTS
----------------------------------
Total Failed Login Attempts: 17
----------------------------------
IP 203.0.113.5 has 8 failed login attempts.
IP 198.51.100.23 has 6 failed login attempts.
```

## How it works

| Function | Purpose |
|---|---|
| `timestamp(line)` | Converts the syslog timestamp into a `datetime` object (adds the current year, since syslog lines don't include one) |
| `get_username(line)` | Finds the username after `for`, handling the `invalid user` variant |
| `key_dictionary(line)` | Builds a dictionary of IP, timestamp and username for one log line |
| `detect_failed_logins(file)` | Groups failed-login events by IP: `{ip: [{timestamp, username}, ...]}` |
| `report(ip_dict, threshold)` | Prints the total failures and IPs meeting the threshold |
| `detailed_report(ip_dict, threshold)` | Prints per-IP detail (unfinished) |

## Known issues

- **Detailed report prints raw dictionaries.** `detailed_report` loops over event dictionaries but prints each one whole, instead of just `event['timestamp']`. The loop variable also shadows the `timestamp()` function.
- **"Targeted usernames" section is empty.** The heading prints, but no usernames are listed yet.
- **No time window.** Detection uses a raw count only, so 5 failures spread over a year are flagged the same as 5 failures in 10 seconds.
- **Successful logins are ignored.** `Accepted password` lines are skipped, so a compromise (success after repeated failures) cannot be detected.
- **Parsing is position-based.** `split()[-4]` for the IP assumes a fixed line layout and will break if the format varies. A regular expression would be more robust.
- **Hardcoded filename.** The log path is fixed to `auth.log`, with no command-line option.
- **Year is assumed.** Timestamps use the current year, which is wrong for logs spanning New Year or from a previous year.
- **Variable naming.** Some names are misleading (e.g. `timestamps` in `report` now refers to event lists).

## Roadmap

- [x] Parse failed logins and group by IP
- [x] Extract timestamp and username per event
- [ ] Fix the detailed report output
- [ ] Time-window detection (N failures within M minutes)
- [ ] Classify password spraying vs brute force by number of unique usernames targeted
- [ ] Detect successful login after repeated failures (possible compromise)
- [ ] Map alerts to MITRE ATT&CK (T1110 Brute Force, T1110.001 Password Guessing, T1110.003 Password Spraying, T1078 Valid Accounts)
- [ ] Command-line arguments (`--threshold`, `--window`, log path)
- [ ] Regex-based parsing
- [ ] Store events in SQLite and express detections as SQL queries
- [ ] Unit tests (pytest)
- [ ] Export alerts to CSV/JSON

## Disclaimer

Intended for educational use and for analysing logs from systems you own or are authorised to monitor.
