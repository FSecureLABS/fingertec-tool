# Fingerpick

This is a tool for communicating with FingerTec access control devices, as well as other ZKTeco based devices.  The options are as follows:

```
$ ./fingerpick.py 
usage: fingerpick.py [-h]
                     {create_user,list_users,brute_force,send_command,open_sesame}
                     ...

positional arguments:
  {create_user,list_users,brute_force,send_command,open_sesame}

optional arguments:
  -h, --help            show this help message and exit
```

## Create User

*create_user* will create a new user on the target device.

```
$ ./fingerpick.py create_user -h
usage: fingerpick.py create_user [-h] [--user_id USER_ID]
                                 [--user_name USER_NAME] [--pin PIN]
                                 [--rfid RFID] [--commkey COMMKEY]
                                 host

positional arguments:
  host                  FingerTec Device IP address

optional arguments:
  -h, --help            show this help message and exit
  --user_id USER_ID     User ID to create. Default is 1337.
  --user_name USER_NAME
                        User name - max of 8 letters.
  --pin PIN             PIN - max of 5 characters. Default 1337.
  --rfid RFID           RFID card number.
  --commkey COMMKEY     COMM Key
```

## List Users

*list_users* will list out all users currently enrolled on device.
```
$ ./fingerpick.py list_users -h 
usage: fingerpick.py list_users [-h] [--brute_force] [--commkey COMMKEY]
                                [--start START] [--end END]
                                host

positional arguments:
  host               FingerTec Device IP address

optional arguments:
  -h, --help         show this help message and exit
  --brute_force      Brute force comm key is necessary
  --commkey COMMKEY  COMM Key
  --start START      Start comm key id
  --end END          End comm key id
```

## Brute Force

*brute_force* will brute force the COMM key (password) on the device.  It will try with every key value from 1 to 99999.  On an AC900, this takes about 3 days to exhaust completely.

```
$ ./fingerpick.py brute_force -h 
usage: fingerpick.py brute_force [-h] [--brute_force] [--start START]
                                 [--end END]
                                 host

positional arguments:
  host           FingerTec Device IP address

optional arguments:
  -h, --help     show this help message and exit
  --brute_force  Brute force comm key is necessary
  --start START  Start comm key id
  --end END      End comm key id
```
## Send Command

*send_command* will send an arbitrary command to a device.  This should be entered as an integer, and will be converted to little endian hex.
```
$ ./fingerpick.py send_command -h 
usage: fingerpick.py send_command [-h] [--commkey COMMKEY] [--fuzz FUZZ]
                                  host command data

positional arguments:
  host               FingerTec Device IP address
  command            Command (integer)
  data               Additional data (args) sent

optional arguments:
  -h, --help         show this help message and exit
  --commkey COMMKEY  COMM Key
```
## Open Sesame

*open_sesame* unlocks the door for a specified amount of time.
```
$ ./fingerpick.py open_sesame -h  
usage: fingerpick.py open_sesame [-h] [--commkey COMMKEY] host delay

positional arguments:
  host               FingerTec Device IP address
  delay              Delay (in seconds) to keep the door open

optional arguments:
  -h, --help         show this help message and exit
  --commkey COMMKEY  COMM Key
```
