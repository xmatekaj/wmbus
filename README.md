# Apator wmbus decoder

### Instalation
pip install -r requirements.txt


### Usage:
  python decode_wmbus.py --keys keys.csv --frames frames.xls
  
  python decode_wmbus.py --keys keys.csv --frames frames.csv
  
  python decode_wmbus.py --keys keys.csv --frames frames.xls --output results.csv
  

### Keys file (CSV, separator ';'):
  Radio number;wMBUS key
  
  12345678;000102030405060708090A0B0C0D0E0F


### Frames file (XLS or CSV):
  XLS: multi-column format (SOF | L | C | M | A | data blocks hex)
  
  CSV (separator ';'):
  
    Detail;Frame_hex
    
    Description;FF61440106785634121A07...
    

### Frame format (binary):
  SOF(FF) + L + C + M(2B) + A(6B) + data_blocks_with_CRC
  
  Encryption: AES-128-CBC (mode 5), IV = M(2B) + A(6B) + TPL_ACC × 8
  
  After decryption: OMS DIF/VIF (2F 2F) + manufacturer data (Apator)
