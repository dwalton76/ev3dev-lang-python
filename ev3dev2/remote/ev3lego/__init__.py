
import logging
import socket
import struct
import time
import threading
import usb.core
from .constants import (
    USB_ID_VENDOR_LEGO,
    USB_ID_PRODUCT_EV3,
    USB_ENDPOINT_IN,
    USB_ENDPOINT_OUT,
    SystemCommand,
    SystemReply,
    opFile
)

log = logging.getLogger(__name__)


def bytes_human_readable(num, suffix='B'):
    for unit in ['','K','M','G','T']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0


def LCX(valueint):
    """create a LC0, LC1, LC2, LC4, dependent from the value"""
    if   value >=    -32 and value <      0:
        return struct.pack('b', 0x3F & (value + 64))
    elif value >=      0 and value <     32:
        return struct.pack('b', value)
    elif value >=   -127 and value <=   127:
        return b'\x81' + struct.pack('<b', value)
    elif value >= -32767 and value <= 32767:
        return b'\x82' + struct.pack('<h', value)
    else:
        return b'\x83' + struct.pack('<i', value)


def LCS(value):
    """
    pack a string into a LCS
    """
    return b'\x84' + str.encode(value) + b'\x00'


def LVX(value):
    """
    create a LV0, LV1, LV2, LV4, dependent from the value
    """
    if value   <     0:
        raise RuntimeError('No negative values allowed')
    elif value <    32:
        return struct.pack('b', 0x40 | value)
    elif value <   256:
        return b'\xc1' + struct.pack('<b', value)
    elif value < 65536:
        return b'\xc2' + struct.pack('<h', value)
    else:
        return b'\xc3' + struct.pack('<i', value)


def GVX(value):
    """create a GV0, GV1, GV2, GV4, dependent from the value"""
    if value   <     0:
        raise RuntimeError('No negative values allowed')
    elif value <    32:
        return struct.pack('<b', 0x60 | value)
    elif value <   256:
        return b'\xe1' + struct.pack('<b', value)
    elif value < 65536:
        return b'\xe2' + struct.pack('<h', value)
    else:
        return b'\xe3' + struct.pack('<i', value)


class RemoteEv3LegoOperatingSystem:
    """
    A class for controlling a remote EV3 running the stock LEGO operating system
    """

    _msg_cnt = 41
    _lock = threading.Lock()
    _foreign = {}

    def __init__(self, protocol, hostmac=None, debug=False):
        self._protocol = protocol
        self._device = None
        self._socket = None
        self.hostmac = hostmac
        self.debug = debug

        if self._protocol == 'wifi':
            self._connect_wifi()

        elif self._protocol == 'usb':
            self._connect_usb()

        elif self._protocol == 'bluetooth':
            self._connect_bluetooth(self.hostmac)

        else:
            raise ValueError("%s is an invald protocol, must be 'wifi', 'usb' or 'bluetooth'" % (self.protocol))

    def __str__(self):
        return "remote EV3 %s" % (self.hostmac)

    def disconnect(self):
        """
        closes the connection to the LEGO EV3
        """
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def _connect_wifi(self):
        log.info("wifi connecting to %s" % self)

        # listen on port 3015 for a UDP broadcast from the EV3
        UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        UDPSock.bind(('', 3015))
        data, addr = UDPSock.recvfrom(67)
        data = data.decode('utf-8')
        (remote_ip, remote_udp_port) = addr

        # Extract serial number, port, name and protocol from message
        data_match = re.search(
            'Serial-Number: (\w*)\s\n' +
            'Port: (\d{4,4})\s\n' +
            'Name: (\w+)\s\n' +
            'Protocol: (\w+)\s\n',
            data)

        if data_match:
            serial_number = data_match.group(1)
            port_for_tcp = int(data_match.group(2))
            name = data_match.group(3)
            protocol = data_match.group(4)

            log.info("connected to remote EV3 %s (%s, %s) via wifi, will use TCP port %d" % (name, remote_ip, remote_port, port_for_tcp))
            log.debug("RXed data '%s'" % (data))

        else:
            raise Exception("wifi UDP response '%s' from %s did not parse correctly" % (data, remote_ip))

        if self.hostmac and serial_number.upper() != self.hostmac.replace(':', '').upper():
            raise ValueError('Found EV3 %s but should have found %s' % (serial_number, self.hostmac))

        # Send a UDP message back to the EV3 to make it accept a TCP/IP connection
        UDPSock.sendto(' '.encode('utf-8'), (remote_ip, port_for_tcp))
        UDPSock.close()

        # Establish a TCP/IP connection with the EV3
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((remote_ip, port_for_tcp))

        # Send an unlock message to the EV3 over TCP/IP
        msg = 'GET /target?sn=' + serial_number + 'VMTP1.0\n' + 'Protocol: ' + protocol
        self._socket.send(msg.encode('utf-8'))
        reply = self._socket.recv(16).decode('utf-8')

        if not reply.startswith('Accept:EV340'):
            raise Exception("wifi TCP response '%s' did not parse correctly" % (reply))

    def _connect_usb (self):
        log.info("usb connecting to %s" % self)

        usb_ev3s = list(usb.core.find(
            find_all=True,
            idVendor=USB_ID_VENDOR_LEGO,
            idProduct=USB_ID_PRODUCT_EV3
        ))

        if self.hostmac is None and len(usb_ev3s) > 1:
            raise Exception("usb found %d bricks via USB but no host MAC " % (len(usb_ev3s)) +\
                "was specified, we do not know which EV3 to connect to")

        for usb_ev3 in usb_ev3s:
            log.info("usb found device\n%s\n" % (usb_ev3))

            if self.hostmac:
                mac_addr = usb.util.get_string(usb_ev3, usb_ev3.iSerialNumber)

                if mac_addr.upper() == self.hostmac.replace(':', '').upper():
                    self._device = usb_ev3
                    break
            else:
                self._device = usb_ev3
                break
        else:
            raise Exception("usb connection failed")

        if self._device.is_kernel_driver_active(0) is True:
            log.info("usb kernel driver is active, detaching")
            self._device.detach_kernel_driver(0)

        self._device.set_configuration()

        # initial read
        USB_MAX_PACKET_BYTES = 1024
        TIMEOUT_MS = 100
        self._device.read(USB_ENDPOINT_IN, USB_MAX_PACKET_BYTES, TIMEOUT_MS)

    def _connect_bluetooth(self, hostmac):
        log.info("bluetooth connecting to %s" % self)

        self._socket = socket.socket(socket.AF_BLUETOOTH,
                                     socket.SOCK_STREAM,
                                     socket.BTPROTO_RFCOMM)
        self._socket.connect((self.hostmac, 1))

    def send_direct_cmd(self, ops, local_mem=0, global_mem=0):
        """
        Send a direct command to the LEGO EV3

        Arguments:
            ops: holds netto data only (operations), the following fields are added:
            length: 2 bytes, little endian
            counter: 2 bytes, little endian
            type: 1 byte, DIRECT_COMMAND_REPLY or DIRECT_COMMAND_NO_REPLY
            header: 2 bytes, holds sizes of local and global memory

        Keyword Arguments:
            local_mem: size of the local memory
            global_mem: size of the global memory

        Returns:
            sync_mode is STD: reply (if global_mem > 0) or message counter
            sync_mode is ASYNC: message counter
            sync_mode is SYNC: reply of the LEGO EV3
        """

        if global_mem > 0  or self._sync_mode == SYNC:
            cmd_type = _DIRECT_COMMAND_REPLY
        else:
            cmd_type = _DIRECT_COMMAND_NO_REPLY

        self._lock.acquire()

        if self._msg_cnt < 65535:
            self._msg_cnt += 1
        else:
            self._msg_cnt = 1

        msg_cnt = self._msg_cnt
        self._lock.release()
        cmd = b''.join([
            struct.pack('<hh', len(ops) + 5, msg_cnt),
            cmd_type,
            struct.pack('<h', local_mem * 1024 + global_mem),
            ops
        ])

        if self.debug:
            log.debug(
                'TXed 0x|' + \
                ':'.join('{:02X}'.format(byte) for byte in cmd[0:2]) + '|' + \
                ':'.join('{:02X}'.format(byte) for byte in cmd[2:4]) + '|' + \
                ':'.join('{:02X}'.format(byte) for byte in cmd[4:5]) + '|' + \
                ':'.join('{:02X}'.format(byte) for byte in cmd[5:7]) + '|' + \
                ':'.join('{:02X}'.format(byte) for byte in cmd[7:]) + '|' \
            )

        # USB
        if self._device is not None:
            self._device.write(USB_ENDPOINT_OUT, cmd, 100)

        # wifi or bluetooth
        elif self._socket is not None:
            self._socket.send(cmd)

        else:
            raise Exception("%s is not connected" % (self))

        counter = cmd[2:4]

        if cmd[4:5] == _DIRECT_COMMAND_NO_REPLY or self._sync_mode == ASYNC:
            return counter

        else:
            reply = self.wait_for_reply(counter)
            return reply

    def wait_for_reply(self, counter):
        """
        Ask the LEGO EV3 for a reply and wait until it is received

        Arguments:
            counter: is the message counter of the corresponding send_direct_cmd

        Returns:
            reply to the direct command
        """
        self._lock.acquire()
        reply = self._get_foreign_reply(counter)

        if reply:
            self._lock.release()
            if reply[4:5] != _DIRECT_REPLY:
                raise DirCmdError(
                    "direct command {:02X}:{:02X} replied error".format(
                        reply[2],
                        reply[3]
                    )
                )
            return reply

        while True:
            # wifi or bluetooth
            if self._socket is not None:
                reply = self._socket.recv(1024)

            # usb
            elif self._device is not None:
                reply = bytes(self._device.read(_EP_IN, 1024, 0))

            else:
                raise Exception("%s is not connected" % (self))

            len_data = struct.unpack('<H', reply[:2])[0] + 2
            reply_counter = reply[2:4]

            if self.debug:
                msg = ' Recv 0x|' + \
                      ':'.join('{:02X}'.format(byte) for byte in reply[0:2]) + \
                      '|' + \
                      ':'.join('{:02X}'.format(byte) for byte in reply[2:4]) + \
                      '|' + \
                      ':'.join('{:02X}'.format(byte) for byte in reply[4:5]) + \
                      '|'

                if len_data > 5:
                    msg += ':'.join('{:02X}'.format(byte) for byte in reply[5:len_data])
                    msg += '|'

                log.debug(msg)

            if counter != reply_counter:
                self._put_foreign_reply(reply_counter, reply[:len_data])
            else:
                self._lock.release()
                if reply[4:5] != _DIRECT_REPLY:
                    raise DirCmdError(
                        "direct command {:02X}:{:02X} replied error".format(
                            reply[2],
                            reply[3]
                        )
                    )
                return reply[:len_data]

    def send_system_cmd(self, cmd: bytes, reply: bool=True) -> bytes:
        """
        Send a system command to the LEGO EV3

        Arguments:
            cmd: holds netto data only (cmd and arguments), the following fields are added:
            length: 2 bytes, little endian
            counter: 2 bytes, little endian
            type: 1 byte, SystemCommand.REPLY or SystemCommand.NO_REPLY

        Keyword Arguments:
            reply: flag if with reply

        Returns:
            reply (in case of SystemCommand.NO_REPLY: counter)
        """

        if reply:
            cmd_type = SystemCommand.REPLY
        else:
            cmd_type = SystemCommand.NO_REPLY

        self._lock.acquire()

        if self._msg_cnt < 65535:
            self._msg_cnt += 1
        else:
            self._msg_cnt = 1

        msg_cnt = self._msg_cnt
        self._lock.release()
        cmd = b''.join([
            struct.pack('<hh', len(cmd) + 3, msg_cnt),
            cmd_type,
            cmd
        ])

        if self.debug:
            log.debug(
                  ' Sent 0x|' + \
                  ':'.join('{:02X}'.format(byte) for byte in cmd[0:2]) + '|' + \
                  ':'.join('{:02X}'.format(byte) for byte in cmd[2:4]) + '|' + \
                  ':'.join('{:02X}'.format(byte) for byte in cmd[4:5]) + '|' + \
                  ':'.join('{:02X}'.format(byte) for byte in cmd[5:]) + '|' \
            )

        # wifi or bluetooth
        if self._socket is not None:
            self._socket.send(cmd)

        # usb
        elif self._device is not None:
            self._device.write(USB_ENDPOINT_OUT, cmd, 100)

        else:
            raise Exception("%s is not connected" % (self))

        counter = cmd[2:4]

        if reply:
            reply = self._wait_for_system_reply(counter)
            return reply
        else:
            return counter

    def _wait_for_system_reply(self, counter: bytes) -> bytes:
        """
        Ask the LEGO EV3 for a system command reply and wait until received

        Arguments:
            counter: is the message counter of the corresponding send_system_cmd

        Returns:
            reply to the system command
        """
        self._lock.acquire()
        reply = self._get_foreign_reply(counter)

        if reply:
            self._lock.release()

            if reply[4:5] != SystemReply.OK:
                raise Exception("error: {:02X}".format(reply[6]))

            return reply

        if self._protocol == 'bluetooth':
            time.sleep(0.1)

        while True:
            # wifi or bluetooth
            if self._socket is not None:
                reply = self._socket.recv(1024)

            # usb
            elif self._device is not None:
                reply = bytes(self._device.read(USB_ENDPOINT_IN, 1024, 0))

            else:
                raise Exception("%s is not connected" % (self))

            len_data = struct.unpack('<H', reply[:2])[0] + 2
            reply_counter = reply[2:4]

            if self.debug:
                msg = 'RXed 0x|' + \
                      ':'.join('{:02X}'.format(byte) for byte in reply[0:2]) + \
                      '|' + \
                      ':'.join('{:02X}'.format(byte) for byte in reply[2:4]) + \
                      '|' + \
                      ':'.join('{:02X}'.format(byte) for byte in reply[4:5]) + \
                      '|' + \
                      ':'.join('{:02X}'.format(byte) for byte in reply[5:6]) + \
                      '|' + \
                      ':'.join('{:02X}'.format(byte) for byte in reply[6:7]) + \
                      '|'

                if len_data > 7:
                    msg += ':'.join('{:02X}'.format(byte) for byte in reply[7:len_data])
                    msg += '|'

                log.debug(msg)

            if counter != reply_counter:
                self._put_foreign_reply(reply_counter, reply[:len_data])
            else:
                self._lock.release()

                if reply[4:5] != SystemReply.OK:
                    raise Exception("system command replied error: {:02X}".format(reply[6]))

                return reply[:len_data]

    def _put_foreign_reply(self, counter, reply):
        """
        put a foreign reply on the stack
        """
        if counter in self._foreign:
            raise Exception('reply with counter %s already exists' % counter)
        else:
            self._foreign[counter] = reply

    def _get_foreign_reply(self, counter):
        """
        get a reply from the stack (returns None if there isn't one)
        and delete this reply from the stack
        """
        if counter in self._foreign:
            reply = self._foreign[counter]
            del self._foreign[counter]
            return reply
        else:
            return None

    def file_write(self, path, data):
        """
        Write data into a file of the EV3's file system

        Attributes:
            path: absolute or relative path (from "/home/root/lms2012/sys/") of the file
            data: data to write into the file
        """
        size = len(data)
        cmd = b''.join([
            SystemCommand.BEGIN_DOWNLOAD,
            struct.pack('<I', size),      # SIZE
            str.encode(path) + b'\x00'    # NAME
        ])
        reply = self.send_system_cmd(cmd)
        handle = struct.unpack('B', reply[7:8])[0]
        rest = size

        while rest > 0:
            part_size = min(1017, rest)
            pos = size - rest
            fmt = 'B' + str(part_size) + 's'
            cmd = b''.join([
                SystemCommand.CONTINUE_DOWNLOAD,
                struct.pack(fmt, handle, data[pos:pos+part_size]) # HANDLE, DATA
            ])
            self.send_system_cmd(cmd)
            rest -= part_size

    def file_read(self, path):
        """
        Read one of EV3's files

        Attributes:
            path: absolute or relative path to file (f.i. "/bin/sh")
        """
        cmd = b''.join([
            SystemCommand.BEGIN_UPLOAD,
            struct.pack('<H', 1012),      # SIZE
            str.encode(path) + b'\x00'    # NAME
        ])
        reply = self.send_system_cmd(cmd)
        (size, handle) = struct.unpack('<IB', reply[7:12])
        part_size = min(1012, size)

        if part_size > 0:
            fmt = str(part_size) + 's'
            data = struct.unpack(fmt, reply[12:])[0]
        else:
            data = b''

        rest = size - part_size

        while rest > 0:
            part_size = min(1016, rest)
            cmd = b''.join([
                SystemCommand.CONTINUE_UPLOAD,
                struct.pack('<BH', handle, part_size) # HANDLE, SIZE
            ])
            reply = self.send_system_cmd(cmd)
            fmt = 'B' + str(part_size) + 's'
            (handle, part) = struct.unpack(fmt, reply[7:])
            data += part
            rest -= part_size

            if rest <= 0 and reply[6:7] != SystemReply.END_OF_FILE:
                raise Exception("end of file not reached")

        return data

    def file_delete(self, path):
        """
        Delete the ``path`` file or directory from the EV3's file system

        Attributes:
            path: absolute path of the file
        """
        cmd = b''.join([
            SystemCommand.DELETE_FILE,
            str.encode(path) + b'\x00'
        ])
        self.send_system_cmd(cmd)

    def file_copy(self, path_source: str, path_dest: str) -> None:
        """
        Copies a file in the EV3's file system from its old location to a new one
        (no error if the file doesn't exist)

        Attributes:
            path_source: absolute or relative path (from "/home/root/lms2012/sys/")
                of the existing file
            path_dest: absolute or relative path of the new file
        """
        ops = b''.join([
            ev3.opFile,
            ev3.MOVE,
            LCS(path_source),
            LCS(path_dest)
        ])
        self.send_direct_cmd(ops, global_mem=1)

    def directory_list(self, path: str) -> dict:
        """
        Read one of EV3's directories

        Attributes:
            path: absolute or relative path to the directory (f.i. "/bin")

        Returns:
            dict, that holds subfolders and files
            {'folders': ['subfolder1', 'subfolder2', ...]
             'files': [{'size': 4202,
                      'name': 'usb-devices',
                      'md5': '5E78E1B8C0E1E8CB73FDED5DE384C000'}, ...]}
        """
        cmd = b''.join([
            SystemCommand.LIST_FILES,
            struct.pack('<H', 1012),      # SIZE
            str.encode(path) + b'\x00'    # NAME
        ])
        reply = self.send_system_cmd(cmd)
        (size, handle) = struct.unpack('<IB', reply[7:12])
        part_size = min(1012, size)

        if part_size > 0:
            fmt = str(part_size) + 's'
            data = struct.unpack(fmt, reply[12:])[0]
        else:
            data = b''

        rest = size - part_size

        while rest > 0:
            part_size = min(1016, rest)
            cmd = b''.join([
                SystemCommand.CONTINUE_LIST_FILES,
                struct.pack('<BH', handle, part_size) # HANDLE, SIZE
            ])
            reply = self.send_system_cmd(cmd)
            fmt = 'B' + str(part_size) + 's'
            (handle, part) = struct.unpack(fmt, reply[7:])
            data += part
            rest -= part_size

            if rest <= 0 and reply[6:7] != SystemReply.END_OF_FILE:
                raise Exception("end of file not reached")

        folders = []
        files = []

        for line in data.split(sep=b'\x0A'):
            if line == b'':
                pass
            elif line.endswith(b'\x2F'):
                folders.append(line.rstrip(b'\x2F').decode("utf8"))
            else:
                (md5, size_hex, name) = line.strip().split()
                size = int(size_hex, 16)
                files.append({
                    'md5': md5.decode("utf8"),
                    'size': size,
                    'name': name.decode("utf8")
                })

        return {'files': files, 'folders': folders}

    def directory_list_pretty(self, path: str) -> str:
        """
        Return a string with a table of information on the files and directories in ``path``.

        Example (for "/home/root/lms2012/sys/"):

          type       size      name               
          =========  ========  ===================
          file       122.0B    ctrl               
          file       153.0B    debug              
          file       330.0B    exit               
          file       330.0B    exit~              
          file       1.3KB     init               
          file       68.0KB    iwconfig           
          file       68.0KB    iwlist             
          directory  N/A       lib                
          file       396.0B    lms                
          file       119.9KB   lms2012            
          directory  N/A       mod                
          file       60.0B     run                
          directory  N/A       settings           
          file       14.4KB    uf2d               
          directory  N/A       ui                 
          file       49.7KB    wpa_cli            
          file       20.7KB    wpa_passphrase     
          file       439.5KB   wpa_supplicant     
          file       444.0B    wpa_supplicant.conf

        """
        dir_content = self.directory_list(path)
        lines = []

        for folder in sorted(dir_content["folders"]):
            lines.append(("directory", "N/A", folder))

        for filedict in dir_content["files"]:
            lines.append(("file", bytes_human_readable(filedict["size"]), filedict["name"]))

        lines.sort(key = lambda line: line[2])
        max_type_len = 0
        max_size_len = 0
        max_name_len = 0

        for (type_, size, name) in lines:
            max_type_len = max(max_type_len, len(type_))
            max_size_len = max(max_size_len, len(size))
            max_name_len = max(max_name_len, len(name))

        result = [""]
        result.append("  %s  %s  %s" % (
            "type".ljust(max_type_len, " "),
            "size".ljust(max_size_len, " "),
            "name".ljust(max_name_len, " ")
        ))
        result.append("  %s  %s  %s" % (
            max_type_len * "=",
            max_size_len * "=",
            max_name_len * "=",
        ))

        for (type_, size, name) in lines:
            result.append("  %s  %s  %s" % (
                type_.ljust(max_type_len, " "),
                size.ljust(max_size_len, " "),
                name.ljust(max_name_len, " ")
            ))

        result.append("")
        return "\n".join(result)

    def directory_create(self, path: str) -> None:
        """
        Create a directory on EV3's file system

        Attributes:
            path: absolute or relative path (from "/home/root/lms2012/sys/")
        """
        cmd = b''.join([
            SystemCommand.CREATE_DIR,
            str.encode(path) + b'\x00'
        ])
        self.send_system_cmd(cmd)

    def directory_delete(self, path: str, secure: bool=True) -> None:
        """
        Delete a directory on EV3's file system

        Attributes:
            path: absolute or relative path (from "/home/root/lms2012/sys/")
            secure: flag, if the directory may be not empty
        """
        if secure:
            self.file_delete(path)
        else:
            if path.endswith("/"):
                path = path[:-1]
            parent_path = path.rsplit("/", 1)[0] + "/"
            folder = path.rsplit("/", 1)[1]
            ops = b''.join([
                opFile,
                SystemCommand.GET_FOLDERS,
                LCS(parent_path),
                GVX(0)
            ])
            reply = self.send_direct_cmd(ops, global_mem=1)
            num = struct.unpack('B', reply[5:])[0]

            for i in range(num):
                ops = b''.join([
                    opFile,
                    SystemCommand.GET_SUBFOLDER_NAME,
                    LCS(parent_path),
                    LCX(i + 1),         # ITEM
                    LCX(64),            # LENGTH
                    GVX(0)              # NAME
                ])
                reply = self.send_direct_cmd(ops, global_mem=64)
                subdir = struct.unpack('64s', reply[5:])[0]
                subdir = subdir.split(b'\x00')[0]
                subdir = subdir.decode("utf8")

                if subdir == folder:
                    ops = b''.join([
                        opFile,
                        ev3.DEL_SUBFOLDER,
                        LCS(parent_path), # NAME
                        LCX(i + 1)        # ITEM
                    ])
                    self.send_direct_cmd(ops)
                    break
            else:
                raise Exception("Folder " + path + " doesn't exist")
