Parses logs of a web interface and builds url request time stats.

Params of of the app could be passed as path to config file.
If no argument passed default config will be used.
Config structure: 

```
{
    "REPORT_SIZE": int,
    "REPORT_DIR": str, #path to report directory
    "LOG_DIR": str #path to directory with logs to parse
}
```

Run the app: 
```
python3 log_analyzer.py --config
```