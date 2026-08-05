from logdb.core.dumpstate import db_make as make_dumpstate
from logdb.core.pcap import db_make as make_pcap
from logdb.core.hci import db_make as make_hci


def db_make(
    log_type: str,
    input_path: str,
    output_path: str,
    force: bool = False
) -> None:
    builders = {
        "dumpstate": make_dumpstate,
        "pcap": make_pcap,
        "hci": make_hci
    }
    return builders[log_type](input_path, output_path, force=force)