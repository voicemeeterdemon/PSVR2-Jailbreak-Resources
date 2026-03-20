import usb1
import ctypes



VID = 0x054C
PID = 0x0CDE

REPORT_ID_SET_AUTH1_DATA = 0xF0
SUB_ID_H_CHALLENGE_1 = 0x01
HID_REQ_SET_REPORT = 0x09

SET_AUTH1_DATA_BLOCK_SIZE = 56
we_want_this_addy = 0x401234



class usb_auth1_data(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("report_id", ctypes.c_uint8),
        ("sub_id", ctypes.c_uint8),
        ("sequence_number", ctypes.c_uint8),
        ("block_number", ctypes.c_uint8),
        ("data", ctypes.c_uint8 * SET_AUTH1_DATA_BLOCK_SIZE),
        ("crc32", ctypes.c_uint32),
    ]


class usb_auth1_data_overflow(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("auth1_data", usb_auth1_data),
        ("extra", ctypes.c_uint8),
    ]


ctx = None
dev = None



def connect():
    global ctx, dev

    ctx = usb1.USBContext()
    ctx.open()

    dev = ctx.openByVendorIDAndProductID(VID, PID)

    if not dev:
        return None

    try:
        dev.setConfiguration(1)
    except:
        pass

    return dev



def hid_set_report(data):

    bmRequestType = 0x21
    wValue = (SUB_ID_H_CHALLENGE_1 << 8) | REPORT_ID_SET_AUTH1_DATA

    try:
        return dev.controlWrite(
            bmRequestType,
            HID_REQ_SET_REPORT,
            wValue,
            0,
            data,
            timeout=0
        )
    except:
        return 0



def hmd2_dummy_set():

    if not dev:
        return 0

    auth = usb_auth1_data()

    auth.report_id = REPORT_ID_SET_AUTH1_DATA
    auth.sub_id = SUB_ID_H_CHALLENGE_1

    payload = ctypes.string_at(ctypes.byref(auth), ctypes.sizeof(auth))

    return hid_set_report(payload)



def hmd2_overflow_val(val):

    if not dev:
        return 0

    overflow = usb_auth1_data_overflow()

    overflow.auth1_data.report_id = REPORT_ID_SET_AUTH1_DATA
    overflow.auth1_data.sub_id = SUB_ID_H_CHALLENGE_1
    overflow.extra = val

    payload = ctypes.string_at(ctypes.byref(overflow), ctypes.sizeof(overflow))

    return hid_set_report(payload)



if __name__ == "__main__":

    connect()

    print("dummy_set returned:", hmd2_dummy_set())
    print("overflow returned:", hmd2_overflow_val(0x8B))