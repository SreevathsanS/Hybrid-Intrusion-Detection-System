# Flow settings
FLOW_TIMEOUT = 10          # seconds before flow expires
SCAN_INTERVAL = 1         # expiry thread scan interval (seconds)

# ML settings
MODEL_PATH = "ips_multiclass_enhanced_model.json"
ENCODER_PATH = "ips_label_enhanced_encoder.pkl"
ATTACK_THRESHOLD = 0.5

BLOCK_DURATION = 60   # seconds
LOG_FILE = "blocked_ips.log"

MAX_ACTIVE_DURATION = 3     # seconds
PACKET_THRESHOLD = 50       # packets

MAX_FLOW_TABLE_SIZE = 10000
