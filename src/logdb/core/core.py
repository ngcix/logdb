from logdb.core.dumpstate import db_make as make_dumpstate
from logdb.core.pcap.db_make import db_make as make_pcap


def db_make(
    log_type: str,
    input_path: str,
    output_path: str
) -> None:
    builders = {
        "dumpstate": make_dumpstate,
        "pcap": make_pcap,
    }
    return builders[log_type](input_path, output_path)