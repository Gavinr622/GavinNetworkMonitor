"""Custom loading-screen settings for Gavin Network Monitor.

Edit this file to customize the splash without changing app.py.
Each loading line is: (status text, detail text, percentage).
Keep percentages between 0 and 100.
"""

MIN_LOADING_SECONDS = 3.0

LOADING_BG = "#171a21"
LOADING_ACCENT = "#66c0f4"
LOADING_TITLE = "GAVIN"
LOADING_SUBTITLE = "NETWORK MONITOR"
SPINNER_INTERVAL_MS = 80

LOADING_LINES = [
    ("Starting Gavin Network Monitor", "Initializing", 10),
    ("Loading saved configuration", "Reading settings", 25),
    ("Loading admin command system", "Preparing commands", 40),
    ("Building application interface", "Creating interface", 58),
    ("Detecting Npcap network interfaces", "Scanning adapters", 78),
    ("Finalizing startup", "Almost ready", 92),
    ("Ready", "Launching monitor", 100),
]
