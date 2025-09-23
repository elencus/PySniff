def format_payload_data(payload, line_length=16):
    # formats the raw payload data into a readable hex/ASCII view
    if not payload:
        return ""

    lines = []
    for i in range(0, len(payload), line_length):
        chunk = payload[i:i + line_length]

        # hex
        hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
        hex_part = hex_part.ljust(line_length * 3 - 1)

        # ascii (replace non-print chars with '.'
        text_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)

        lines.append(f"\t\t\t\t{hex_part}  |{text_part}|")
    return "\t\t\t[+] Payload Data: \n" + "\n".join(lines)
