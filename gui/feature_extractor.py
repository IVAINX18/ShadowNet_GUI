import pefile
import numpy as np
import os
from typing import Optional

class FeatureExtractor:
    def __init__(self):
        pass

    def extract_features(self, file_path: str) -> Optional[np.ndarray]:
        """
        Extrae características de un archivo PE (Windows executable)
        Retorna un array de features o None si falla
        """
        try:
            pe = pefile.PE(file_path)
            features = []

            # Características básicas del header
            features.append(pe.FILE_HEADER.Machine)
            features.append(pe.FILE_HEADER.NumberOfSections)
            features.append(pe.FILE_HEADER.TimeDateStamp)
            features.append(pe.FILE_HEADER.PointerToSymbolTable)
            features.append(pe.FILE_HEADER.NumberOfSymbols)
            features.append(pe.FILE_HEADER.SizeOfOptionalHeader)
            features.append(pe.FILE_HEADER.Characteristics)

            # Características del Optional Header
            if hasattr(pe, 'OPTIONAL_HEADER'):
                features.append(pe.OPTIONAL_HEADER.Magic)
                features.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
                features.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
                features.append(pe.OPTIONAL_HEADER.SizeOfCode)
                features.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
                features.append(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
                features.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                features.append(pe.OPTIONAL_HEADER.BaseOfCode)
                features.append(pe.OPTIONAL_HEADER.ImageBase)
                features.append(pe.OPTIONAL_HEADER.SectionAlignment)
                features.append(pe.OPTIONAL_HEADER.FileAlignment)
                features.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
                features.append(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
                features.append(pe.OPTIONAL_HEADER.MajorImageVersion)
                features.append(pe.OPTIONAL_HEADER.MinorImageVersion)
                features.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
                features.append(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
                features.append(pe.OPTIONAL_HEADER.SizeOfImage)
                features.append(pe.OPTIONAL_HEADER.SizeOfHeaders)
                features.append(pe.OPTIONAL_HEADER.CheckSum)
                features.append(pe.OPTIONAL_HEADER.Subsystem)
                features.append(pe.OPTIONAL_HEADER.DllCharacteristics)
                features.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
                features.append(pe.OPTIONAL_HEADER.SizeOfStackCommit)
                features.append(pe.OPTIONAL_HEADER.SizeOfHeapReserve)
                features.append(pe.OPTIONAL_HEADER.SizeOfHeapCommit)
                features.append(pe.OPTIONAL_HEADER.LoaderFlags)
                features.append(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)

            # Características de las secciones
            section_features = []
            for section in pe.sections:
                section_features.extend([
                    section.VirtualAddress,
                    section.Misc_VirtualSize,
                    section.SizeOfRawData,
                    section.PointerToRawData,
                    section.PointerToRelocations,
                    section.PointerToLinenumbers,
                    section.NumberOfRelocations,
                    section.NumberOfLinenumbers,
                    section.Characteristics
                ])

            # Padding para tener siempre el mismo número de features
            max_sections = 5
            section_feature_size = 9
            if len(pe.sections) < max_sections:
                padding = [0] * (section_feature_size * (max_sections - len(pe.sections)))
                section_features.extend(padding)
            else:
                section_features = section_features[:max_sections * section_feature_size]

            features.extend(section_features)

            # Imports
            num_imports = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    num_imports += len(entry.imports)
            features.append(num_imports)

            # Exports
            num_exports = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                num_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            features.append(num_exports)

            # Tamaño del archivo
            features.append(os.path.getsize(file_path))

            pe.close()

            return np.array(features, dtype=np.float32)

        except Exception as e:
            print(f"Error extrayendo características: {e}")
            return None
