"""A global pool of containers for OFG to pull from to enable quick rebuilding of harnesses and docker container reuse"""

import logging
from dataclasses import dataclass
from multiprocessing import Lock, Value
from typing import Any, Optional

from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark
from tool.container_tool import ProjectContainerTool


@dataclass
class ContainerPair:
    address_container: ProjectContainerTool
    coverage_container: ProjectContainerTool
    in_use: Any


class ContainerPool:
    """This class represents a pool of containers. Each item in the pool has one container instrumented with ASAN and one for coverage"""

    def __init__(self, benchmark: Benchmark, num_exp: int, num_evals: int):
        self.lock = Lock()  # Works across processes when created before fork
        self.containers = []
        logging.info(
            "Initializing %d container pairs for the trial", num_exp * num_evals
        )
        for _ in range(num_exp * num_evals):
            self.containers.append(self.create_container_pair(benchmark))

    def create_container_pair(self, benchmark: Benchmark) -> ContainerPair:
        address = ProjectContainerTool(benchmark=benchmark)

        oss_fuzz_checkout.ENABLE_CACHING = False
        coverage = ProjectContainerTool(benchmark=benchmark)
        oss_fuzz_checkout.ENABLE_CACHING = True

        in_use = Value("b", False)

        return ContainerPair(address, coverage, in_use)

    def get_container_pair(self) -> Optional[ContainerPair]:
        with self.lock:
            for pair in self.containers:
                if not pair.in_use.value:
                    pair.in_use.value = True
                    return pair
        return None

    def release_container_pair(self, pair: ContainerPair):
        with self.lock:
            pair.in_use.value = False
