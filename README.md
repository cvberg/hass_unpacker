Home Assistant Backup decoder and unpacker
=================================================================================

Home Assistant backups are now encrypted by default.  
This little tool will decrypt and unpack all or parts of the backup.  
You must copy the encryption key from Home Assistant.  
Without the key, this tool is useless.  

Make sure you have Python 3.10 or higher, with "securetar" included.  
If not present, install with:  `pip install securetar`


For usage instructions, run the script without parameters:  
`python3 hass_unpacker.py`
