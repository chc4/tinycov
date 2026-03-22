import io
import sys
import collections
import typing

class CoverageItem(collections.OrderedDict):
    timestamp: int
    rip: int
    rflags: int
    target: typing.Optional[int] = None

    def __repr__(self):
        if self.target:
            after = f" -> {self.target:x}"
        else:
            after = ""
        return f"{self.timestamp:x} item {self.rip:x} {self.rflags:x}" + after

def process_trace(path):
    log = dict()
    ring = {}
    dictionary = set()
    draining = True
    drain_index = 0

    def finalize_ring():
        nonlocal ring
        nonlocal drain_index
        # done draining the trace log
        for i,v in sorted(ring.items()):
            #print(i, v)
            log[v.timestamp] = v
        ring = {}
        drain_index = 0

    with io.open(path, "r") as f:
        while line := f.readline():
            line = line.strip()
            was_draining = draining
            #print(line)
            words = line.split(" ")
            if words[0] == "drain":
                # draining precise buffer
                draining = True
                item = ring.setdefault(drain_index, CoverageItem())
                item.timestamp = int(words[1], 16)
                item.rip = int(words[2], 16)
                item.rflags = int(words[3], 16)
                drain_index = drain_index + 0x20
                continue
            else:
                if draining:
                    finalize_ring()
                    draining = False
                item = ring.setdefault(int(words[0], 16), CoverageItem())

            if words[1] == "cmpcov":
                # cmpcov dictionary item
                item.rip = int(words[2], 16)
                item.rflags = 0
                pass
            elif words[1] == "dyncall":
                # dynamic call item
                item.rip = int(words[2], 16)
                item.rflags = 0
                item.target = int(words[4], 16)
                pass
            else:
                # normal coverage
                item.rip = int(words[1], 16)
                item.rflags = int(words[2], 16)
    finalize_ring()

    for i,v in sorted(log.items()):
        print(v)

if __name__=="__main__":
    process_trace(sys.argv[1])
