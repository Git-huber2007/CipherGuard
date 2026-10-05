"""Native Windows WLAN AutoConfig (WlanApi) scanner.

Forces the Wi-Fi interface to actively send 802.11 Probe Requests across all
channels and refresh the Windows BSSID cache.
"""

from __future__ import annotations

import ctypes
import sys
import time

is_windows = sys.platform.startswith("win")

if is_windows:
    try:
        from ctypes import wintypes
        wlanapi = ctypes.windll.wlanapi

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8),
            ]

        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [
                ("InterfaceGuid", GUID),
                ("strInterfaceDescription", wintypes.WCHAR * 256),
                ("isState", wintypes.DWORD),
            ]

        class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [
                ("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
            ]

    except Exception:
        wlanapi = None
else:
    wlanapi = None


def trigger_scan(wait_secs: float = 1.5) -> bool:
    """Trigger an active 802.11 probe scan on all wireless adapters.

    Returns True if WlanScan was successfully accepted by the WLAN service.
    """
    if not is_windows or not wlanapi:
        return False

    handle = wintypes.HANDLE()
    negotiated = wintypes.DWORD()
    try:
        res = wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle))
        if res != 0:
            return False

        p_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        res = wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(p_list))
        if res != 0 or not p_list:
            wlanapi.WlanCloseHandle(handle, None)
            return False

        count = p_list.contents.dwNumberOfItems
        if count == 0:
            wlanapi.WlanCloseHandle(handle, None)
            return False

        success = False

        class REAL_LIST(ctypes.Structure):
            _fields_ = [
                ("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * count),
            ]

        real_p_list = ctypes.cast(p_list, ctypes.POINTER(REAL_LIST))
        for i in range(count):
            guid = real_p_list.contents.InterfaceInfo[i].InterfaceGuid
            r = wlanapi.WlanScan(handle, ctypes.byref(guid), None, None, None)
            if r == 0:
                success = True

        wlanapi.WlanCloseHandle(handle, None)

        if success and wait_secs > 0:
            time.sleep(wait_secs)

        return success
    except Exception:
        return False
