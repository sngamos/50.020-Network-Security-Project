# Get Suricata container IP
SURICATA_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' suricata_ids)
echo "Suricata IP: $SURICATA_IP"

# Get ML-IDS container IP
ML_IDS_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ml_ids)
echo "ML-IDS IP: $ML_IDS_IP"

