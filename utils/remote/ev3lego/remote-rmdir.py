
import logging
import sys
from pprint import pformat
from ev3lego import RemoteEv3LegoOperatingSystem


logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(filename)22s %(levelname)8s: %(message)s"
)
log = logging.getLogger(__name__)
 
#rev3 = RemoteEv3LegoOperatingSystem("usb", debug=True)
rev3 = RemoteEv3LegoOperatingSystem("bluetooth", hostmac="00:16:53:3F:8F:D1", debug=True)

dir_name = sys.argv[1]
rev3.directory_delete(dir_name)
rev3.disconnect()
