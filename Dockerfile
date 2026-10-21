# netcut-linux - image mandiri
#
# Tidak ada mount filesystem host yang dibutuhkan: Python, scapy, nftables,
# dan database OUI semuanya sudah ada di dalam image. Yang perlu dibagi
# dengan host hanya network namespace-nya (--network=host), karena ARP
# spoofing dan relay harus bekerja pada interface host yang asli.
#
#   docker build -t netcut-linux .
#   docker run --rm -d --name netcut \
#     --network=host \
#     --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     netcut-linux
#
# Dashboard: http://127.0.0.1:8080
FROM debian:trixie-slim

LABEL org.opencontainers.image.title="netcut-linux" \
      org.opencontainers.image.description="Monitor bandwidth per host & kontrol trafik jaringan lokal" \
      org.opencontainers.image.licenses="MIT"

# python3-scapy : capture paket + ARP scan
# nftables      : aturan drop / rate-limit
# iproute2      : ip route, ip neigh
# iptables      : deteksi policy firewall host
# iputils-ping  : dipakai test suite untuk cek konektivitas
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-scapy \
        nftables \
        iproute2 \
        iptables \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Database OUI. Paket hwdata di Debian tidak menyertakan oui.txt (di Fedora
# ada di /usr/share/hwdata/oui.txt), jadi dipakai file dari build context
# (assets/oui.txt). Kalau file itu tidak ada, coba unduh dari daftar resmi
# IEEE lalu konversi.
#
# Refresh assets/oui.txt:
#   curl -sL https://standards-oui.ieee.org/oui/oui.csv -o /tmp/oui.csv
#   python3 tools/oui_csv_to_hwdata.py /tmp/oui.csv assets/oui.txt
RUN mkdir -p /usr/share/hwdata \
    && if [ -s /app/assets/oui.txt ]; then \
         cp /app/assets/oui.txt /usr/share/hwdata/oui.txt \
         && echo "database OUI dari build context"; \
       else \
         python3 -c "import urllib.request; \
urllib.request.urlretrieve('https://standards-oui.ieee.org/oui/oui.csv','/tmp/oui.csv')" \
         && python3 /app/tools/oui_csv_to_hwdata.py /tmp/oui.csv /usr/share/hwdata/oui.txt \
         && rm -f /tmp/oui.csv \
         || echo "PERINGATAN: database OUI gagal diambil, vendor akan unknown"; \
       fi

# Hanya sebagai sinyal; binding sebenarnya tetap 127.0.0.1 supaya dashboard
# tidak terbuka ke jaringan. Dengan --network=host, 127.0.0.1 di container
# = 127.0.0.1 di host.
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/hosts',timeout=4).status==200 else 1)"

ENTRYPOINT ["python3", "/app/netcut.py"]
CMD ["--web", "--web-port", "8080"]
