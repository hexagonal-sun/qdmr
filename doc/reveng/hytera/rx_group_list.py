import struct
from typing import Dict, List, Any
from section import CPSSection
from util import chunks
from contact import parse_digital_contacts


class ContactPointer:
    STRUCT_FMT = 'I'

    def __init__(self, data: bytes) -> None:
        self.addr = struct.unpack(ContactPointer.STRUCT_FMT, data)[0]

    def __eq__(self, o: Any) -> bool:
        if not isinstance(o, ContactPointer):
            return False

        return (o.addr == self.addr)

    @staticmethod
    def size() -> int:
        """Return the size of the element in the codeplug."""
        return struct.calcsize(ContactPointer.STRUCT_FMT)


class RxGroupListName:
    """Represents a RX group list name in the codeplug."""
    STRUCT_FMT = '<32s'

    def __init__(self, data: bytes, pointers: List[ContactPointer]) -> None:
        fields = struct.unpack(RxGroupListName.STRUCT_FMT, data)
        self.name = fields[0].decode('utf-8')
        self.pointers = pointers

    @staticmethod
    def size() -> int:
        """Return the size of the element in the codeplug."""
        return struct.calcsize(RxGroupListName.STRUCT_FMT)


def parse_rx_group_lists(cps: Dict[int, CPSSection]) -> Dict[int, RxGroupListName]:
    gn_section = cps.get(0x6C)
    gp_section = cps.get(0x2B)

    if gn_section is None:
        raise RuntimeError("No grouplist name section found in codeplug.")

    if gp_section is None:
        raise RuntimeError("No grouplist pointer section found in clodeplug.")

    # There should be a list of grouplist pointers for every grouplist.
    assert gn_section.header.no_elements == gp_section.header.no_elements

    num_GLs = gn_section.header.no_elements

    def read_group_list(data: bytes, idx: int) -> List[ContactPointer]:
        start_addr = i * 0x28e

        header_data = struct.unpack('<HHHII', data[start_addr:start_addr+0xe])

        assert header_data[1] == 0x40
        assert header_data[3] == 0x100
        assert header_data[4] == 0x10e

        num_pointers = header_data[2]

        pointers = []

        for ptr_data in chunks(data[start_addr+0xe:start_addr+0xe + (num_pointers * ContactPointer.size())],
                               ContactPointer.size()):
            pointers.append(ContactPointer(ptr_data))

        return pointers

    gl_names = []

    for i, data in enumerate(chunks(gn_section.data, RxGroupListName.size())[:num_GLs]):
        pointer_list = read_group_list(gp_section.data, i)
        scan_list = RxGroupListName(data, pointer_list)
        gl_names.append(scan_list)

    ret = dict()

    # Calculate mappings
    for i, idx in enumerate(gn_section.mappings[:num_GLs]):
        ret[i] = gl_names[idx]

    return ret


def print_group_lists(cps: Dict[int, CPSSection]) -> None:
    group_lists = parse_rx_group_lists(cps)
    contacts = parse_digital_contacts(cps)

    for group_list in group_lists.values():
        print("Grouplist: {}".format(group_list.name))
        for pointer in group_list.pointers:
            print("  addr: {:02X} contact:{}".format(pointer.addr,
                                                     contacts[pointer.addr - 1].name))
