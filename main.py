from capture_packets import capture_packets

def main():
    try:
        # Call the capture function from capture.py
        capture_packets()

    except KeyboardInterrupt:
        print("Exiting gracefully...")

if __name__ == "__main__":
    main()
