# Big Brainalyze

It does static analysis of malware. I've only used it on a Flare-VM, but at a minimum it requires flarestrings and floss installed on a Windows machine.

Oh yeah, it needs a `config.py` file with your VirusTotal API key.

```
vt_keys = ["key goes here"]
```

## Usage

```
python3 BigBrainalyzer.py <path to directory of samples>
```

Samples must be unzipped. The final step of BigBrainalyzer zips the malware with the password `infected`

There's very little error handling or comments, so good luck. Feel free to make PRs, ping me on discord, steal some or all of this, whatever.
