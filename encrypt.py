import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from scapy.all import sniff, IP, TCP, UDP

# App Title
st.title("🔐 Secure Data Handling with PyCryptodome & Scapy")

# Sidebar Navigation
option = st.sidebar.radio("Select an Option", ["🔒 Encrypt & Decrypt Data", "🌐 Network Packet Sniffer"])

# 🔒 **Encryption & Decryption**
if option == "🔒 Encrypt & Decrypt Data":
    st.header("AES Encryption & Decryption")

    # Generate a Random AES Key
    key = get_random_bytes(16)
    st.text("Generated AES Key (Keep Secure!):")
    st.code(base64.b64encode(key).decode(), language="plaintext")

    # Input Text for Encryption
    text = st.text_area("Enter text to encrypt")

    if st.button("Encrypt"):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(text.encode())
        encrypted_data = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
        st.success("🔒 Encrypted Data:")
        st.code(encrypted_data, language="plaintext")

    # Input Encrypted Data for Decryption
    encrypted_text = st.text_area("Enter encrypted text to decrypt")

    if st.button("Decrypt"):
        try:
            decoded_data = base64.b64decode(encrypted_text)
            nonce, tag, ciphertext = decoded_data[:16], decoded_data[16:32], decoded_data[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag).decode()
            st.success("🔓 Decrypted Text:")
            st.code(decrypted_data, language="plaintext")
        except Exception as e:
            st.error(f"Decryption Failed: {str(e)}")

# 🌐 **Network Packet Sniffer**
elif option == "🌐 Network Packet Sniffer":
    st.header("🌐 Network Packet Sniffer with Scapy")
    packet_count = st.slider("Number of Packets to Capture", min_value=1, max_value=10, value=5)

    if st.button("Start Sniffing"):
        st.warning("Sniffing network packets... Please wait.")

        # Capture Network Packets
        packets = sniff(count=packet_count, filter="ip", timeout=5)

        packet_data = []
        for pkt in packets:
            if IP in pkt:
                protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
                packet_data.append({
                    "Source IP": pkt[IP].src,
                    "Destination IP": pkt[IP].dst,
                    "Protocol": protocol,
                    "Packet Size": len(pkt)
                })

        # Display Captured Packets
        if packet_data:
            df = pd.DataFrame(packet_data)
            st.dataframe(df)
        else:
            st.info("No packets captured. Try increasing the capture count.")

