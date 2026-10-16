from dataclasses import dataclass, asdict

@dataclass
class TokenModel:
    index: int
    type: str
    value: str
    line: int
    column: int
    categoria: str
    regex: str
    quintupla_afd: dict
    quintupla_afnd: dict
    jflap_afd_svg: str
    jflap_afnd_svg: str
    jflap_runs: list
    syn_tree_svg: str
    sem_tree_svg: str
    paren_rep: str
    sem_ok: bool
    sem_msg: str

    def to_dict(self):
        return asdict(self)