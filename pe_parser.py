from flag_to_string import MACHINES, CHARACTERISTICS, DLLS, SUBSYSTEMS, SECTIONS

from datetime import datetime
import pefile
import os

def prntline():
  return '---------------------------------------------\n'

def write_header_info(pe, f):
  dos = pe.DOS_HEADER
  fhead = pe.FILE_HEADER
  option = pe.OPTIONAL_HEADER

  f.write('\nDOS Header:\n')
  f.write(prntline())
  f.write(f'Magic Bytes: {hex(dos.e_magic)}\n')
  f.write(f'e_lfanew (Start of PE Header): {hex(dos.e_lfanew)}\n')

  f.write('\nFile Headers:\n')
  f.write(prntline())
  f.write(f"Machine: {hex(fhead.Machine)} {MACHINES[fhead.Machine]}\n")
  f.write(f"Number of sections: {fhead.NumberOfSections}\n")
  f.write('- File Characteristics -\n')
  ch = pe.FILE_HEADER.Characteristics
  for k,d in CHARACTERISTICS.items():
    if k & ch:
      f.write(d + '\n')
  
  f.write('\nOptional Headers\n')
  prntline()
  t = datetime.fromtimestamp(fhead.TimeDateStamp)
  f.write(f"Magic: {hex(option.Magic)}\n")
  f.write(f"Timestamp: {t}\n")
  f.write(f"AddressOfEntryPoint: {hex(option.AddressOfEntryPoint)}\n")
  f.write(f"ImageBase: {hex(option.ImageBase)}\n")
  f.write(f"SectionAlignment: {hex(option.SectionAlignment)}\n")
  f.write(f"SizeOfImage in memory: {(option.SizeOfImage / 1000):.2f} KB\n")
  f.write(f"Subsystem: {SUBSYSTEMS[option.Subsystem]}\n")
  och = option.DllCharacteristics
  f.write('- DLL Characteristics -\n')
  for k,d in DLLS.items():
    if k & och:
      f.write(d + '\n')


def is_packed(pe):
  for s in pe.sections:
    if s.Misc_VirtualSize - s.SizeOfRawData > 0 and s.IMAGE_SCN_MEM_EXECUTE and s.IMAGE_SCN_MEM_WRITE:
      return True
  return False


def write_sections(pe, f):
  packed = False
  f.write('\nSections\n')
  f.write(prntline())
  for s in pe.sections:
    f.write(f'\n- {s.Name} -\n')
    f.write(f'Virtual Size: {s.Misc_VirtualSize}\n')
    f.write(f'Raw Size {s.SizeOfRawData}\n')
    f.write(f'Entropy: {s.get_entropy()}\n')
    f.write(f'MD5: {s.get_hash_md5()}\n')
    f.write(f'SHA1: {s.get_hash_sha1()}\n')
    f.write(f'SHA256: {s.get_hash_sha256()}\n')
    f.write('- Characteristics -\n')
    ch = s.Characteristics
    for k,d in SECTIONS.items():
      if k & ch:
        f.write(d + '\n')


def write_imports(pe, f):
  f.write('\nImports\n')
  prntline()
  pe.parse_data_directories()
  f.write(f'Import Hash: {pe.get_imphash()}\n')
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
    f.write(f'- {entry.dll} -\n')
    for imp in entry.imports:
      f.write(f'\t{hex(imp.address)} {imp.name}\n')


def write_basic_info(pe, f):
  if pe.is_dll():
    f.write('File Type: DLL\n')
  if pe.is_driver():
    f.write('File Type: Driver\n')
  if pe.is_exe():
    f.write('File Type: EXE\n')
  if is_packed(pe):
    f.write('File is likely packed\n')


def write_pe_structure(filename, outdir):
  with open(f'{outdir}\\pe_structure.txt', 'w') as f:
    pe = pefile.PE(filename)
    f.write(f'PE Structure Information for {filename} - {datetime.now().strftime("%m-%d-%Y")}\n')
    write_basic_info(pe,f)
    write_header_info(pe, f)
    write_sections(pe, f)
    write_imports(pe, f)

  with open(f'{outdir}\\full_dump_pe_structure.txt', 'w') as f:
    f.write(pe.dump_info())
