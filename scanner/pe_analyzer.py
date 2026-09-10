"""
SecureCloud - PE Binary & EMBER Feature Analyzer
Parses Portable Executable (PE) headers, sections, exports, imports, and entropy using pefile.
"""

import math
from typing import Dict, Any, List, Optional
import pefile

def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

class PEAnalyzer:
    """Extracts structural PE features and security indicators for EMBER / LightGBM models."""

    @staticmethod
    def is_pe_binary(data: bytes) -> bool:
        """Determines if the raw byte stream starts with the DOS 'MZ' header signature."""
        return len(data) >= 64 and data[:2] == b"MZ"

    @staticmethod
    def analyze_pe(data: bytes, filename: str) -> Dict[str, Any]:
        """
        Parses PE binary structures and extracts security features.
        """
        if not PEAnalyzer.is_pe_binary(data):
            return {
                "is_pe": False,
                "error": "Not a valid Portable Executable (PE) binary"
            }

        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories()

            # 1. Header Information
            num_sections = pe.FILE_HEADER.NumberOfSections
            timestamp = pe.FILE_HEADER.TimeDateStamp
            machine = hex(pe.FILE_HEADER.Machine)
            characteristics = pe.FILE_HEADER.Characteristics

            # 2. Section Analysis & Section Entropies
            sections_info = []
            max_section_entropy = 0.0
            has_executable_high_entropy = False

            for s in pe.sections:
                s_name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                s_entropy = s.get_entropy()
                s_size = s.SizeOfRawData
                s_char = s.Characteristics
                is_executable = bool(s_char & 0x20000000)

                max_section_entropy = max(max_section_entropy, s_entropy)
                if is_executable and s_entropy > 7.1:
                    has_executable_high_entropy = True

                sections_info.append({
                    "name": s_name,
                    "entropy": round(s_entropy, 3),
                    "size": s_size,
                    "is_executable": is_executable
                })

            # 3. Import / Export counts
            num_imports = 0
            suspicious_apis_found = []
            suspicious_api_patterns = {
                "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
                "IsDebuggerPresent", "WinExec", "ShellExecute", "URLDownloadToFile",
                "HttpSendRequest", "CryptEncrypt", "SetWindowsHookEx"
            }

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        num_imports += 1
                        if imp.name:
                            name_str = imp.name.decode("utf-8", errors="ignore")
                            for pattern in suspicious_api_patterns:
                                if pattern.lower() in name_str.lower():
                                    suspicious_apis_found.append(name_str)

            num_exports = 0
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
                num_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

            pe.close()

            return {
                "is_pe": True,
                "num_sections": num_sections,
                "timestamp": timestamp,
                "machine": machine,
                "characteristics": characteristics,
                "max_section_entropy": round(max_section_entropy, 3),
                "has_executable_high_entropy": has_executable_high_entropy,
                "num_imports": num_imports,
                "num_exports": num_exports,
                "suspicious_apis": list(set(suspicious_apis_found)),
                "sections": sections_info
            }

        except Exception as e:
            return {
                "is_pe": True,
                "error": f"PE structure parsing error: {str(e)}",
                "num_sections": 0,
                "max_section_entropy": calculate_entropy(data),
                "has_executable_high_entropy": False,
                "num_imports": 0,
                "num_exports": 0,
                "suspicious_apis": []
            }
