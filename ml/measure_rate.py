import json, subprocess, sys, time, urllib.request
V = sys.argv[1]
def fc():
    d = json.load(urllib.request.urlopen("http://localhost:8080/api/devices"))
    return next((x["flow_count"] for x in d if x["ip"] == "172.17.0.1"), 0)
time.sleep(3); base = fc(); t0 = time.time()
subprocess.run(["sudo", "nmap", "-sS", "-Pn", "-T4", "-p", "1-1024", V], stdout=subprocess.DEVNULL)
last = fc(); t_last = time.time()
while time.time() - t_last < 6:
    time.sleep(1); n = fc()
    if n != last: last, t_last = n, time.time()
done = last - base; el = t_last - t0
print(f"processed {done} flows in {el:.1f}s -> {done/el:.0f} flows/s")
