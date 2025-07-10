from flask import Flask, render_template, jsonify, request
import psutil, time, random, threading
import pyshark

app = Flask(__name__)

# Bandwidth tracking
prev_sent = psutil.net_io_counters().bytes_sent
prev_recv = psutil.net_io_counters().bytes_recv
prev_time = time.time()
attack_mode = False  # Simulated attack flag

# Protocol counters
protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

# Adjust interface for your system
INTERFACE = "Ethernet"  # Or "Ethernet" if on wired. Run helper to see available interfaces.


def packet_sniffer():
    global protocol_counts

    try:
        cap = pyshark.LiveCapture(interface=INTERFACE)
        print(f"✅ Capturing on interface: {INTERFACE}")
    except Exception as e:
        print(f"[ERROR] Could not open interface '{INTERFACE}': {e}")
        return

    for pkt in cap.sniff_continuously():
        proto = "Other"
        try:
            if 'TCP' in pkt:
                proto = "TCP"
            elif 'UDP' in pkt:
                proto = "UDP"
            elif 'ICMP' in pkt:
                proto = "ICMP"
        except Exception:
            pass

        protocol_counts[proto] += 1

        # Optional: log every 50 packets to confirm activity
        total = sum(protocol_counts.values())
        if total % 50 == 0:
            print(f"📊 Protocol counts so far: {protocol_counts}")


# ✅ Start sniffer thread AFTER function is defined
threading.Thread(target=packet_sniffer, daemon=True).start()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/traffic")
def traffic():
    global prev_sent, prev_recv, prev_time, attack_mode

    curr_sent = psutil.net_io_counters().bytes_sent
    curr_recv = psutil.net_io_counters().bytes_recv
    curr_time = time.time()

    elapsed = curr_time - prev_time
    if elapsed == 0:  # avoid division by zero
        elapsed = 1

    upload_rate = (curr_sent - prev_sent) / elapsed
    download_rate = (curr_recv - prev_recv) / elapsed

    prev_sent, prev_recv, prev_time = curr_sent, curr_recv, curr_time

    if attack_mode:
        upload_rate += random.randint(500000, 1000000)
        download_rate += random.randint(500000, 1000000)

    return jsonify({
        "upload": round(upload_rate, 2),
        "download": round(download_rate, 2),
        "timestamp": time.strftime("%H:%M:%S"),
        "attack": attack_mode
    })


@app.route("/api/attack", methods=["POST"])
def attack():
    global attack_mode
    mode = request.json.get("mode")
    attack_mode = True if mode == "on" else False
    return jsonify({"attack": attack_mode})


@app.route("/api/protocols")
def protocols():
    return jsonify(protocol_counts)


if __name__ == "__main__":
    print("✅ Network Traffic Analyzer running…")
    print("🌐 Visit: http://127.0.0.1:5000/")
    app.run(debug=True, host="0.0.0.0", port=5000)
