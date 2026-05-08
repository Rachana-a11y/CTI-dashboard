# import re


# def normalize_ioc(ioc: str) -> str:
#     """
#     Normalize the IOC:
#     - Remove spaces
#     - Convert to lowercase
#     """
#     return ioc.strip().lower()


# def detect_ioc_type(ioc: str) -> str:
#     """
#     Detect IOC type:
#     - IP
#     - Domain
#     - MD5 / SHA1 / SHA256
#     """

#     # 🔹 IP Address
#     if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ioc):
#         return "ip"

#     # 🔹 Hashes
#     if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
#         return "md5"

#     if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
#         return "sha1"

#     if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
#         return "sha256"

#     # 🔹 Domain
#     if re.fullmatch(
#         r"(?=.{1,253}$)((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}",
#         ioc
#     ):
#         return "domain"

#     return "unknown"


# def is_valid_ioc(ioc: str) -> bool:
#     """
#     Check if IOC is valid.
#     """
#     return detect_ioc_type(ioc) != "unknown"

import re
import ipaddress

def normalize_ioc(ioc: str) -> str:
    return ioc.strip().lower()

def detect_ioc_type(ioc: str) -> str:
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    if re.fullmatch(r"[a-f0-9]{32}", ioc):
        return "md5"
    elif re.fullmatch(r"[a-f0-9]{40}", ioc):
        return "sha1"
    elif re.fullmatch(r"[a-f0-9]{64}", ioc):
        return "sha256"
    elif re.fullmatch(r"(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+", ioc):
        return "domain"

    return "unknown"

def is_valid_ioc(ioc: str) -> bool:
    return detect_ioc_type(ioc) != "unknown"