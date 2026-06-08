from typing import Protocol


class Arch(Protocol):
    def pc_register_name(self) -> str: ...
    def all_register_names(self) -> list[str]: ...


class AMD64(Arch):
    def pc_register_name(self) -> str:
        return "rip"

    def all_register_names(self) -> list[str]:
        return [
            "rip",
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rbp",
            "rsp",
            "rsi",
            "rdi",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
        ]


class ARM64(Arch):
    def pc_register_name(self) -> str:
        return "pc"

    def all_register_names(self) -> list[str]:
        xs = [f"x{i}" for i in range(29)]
        return ["pc", "sp", "lr", "fp"] + xs


def detect_arch() -> Arch:
    proc_name = None
    try:
        # for 8.+
        import idaapi

        proc_name = idaapi.get_inf_structure().procname
    except Exception:
        pass

    if proc_name is None:
        try:
            # for 9.+
            import ida_ida

            proc_name = ida_ida.inf_get_procname()
        except Exception:
            pass

    if proc_name is None:
        raise Exception("Unable to detect CPU Arch :/")

    if proc_name == "ARM":
        return ARM64()
    elif proc_name == "metapc":
        return AMD64()
    else:
        raise Exception(f"Unknown CPU Arch '{proc_name}' :/")
